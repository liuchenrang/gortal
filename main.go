package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/TNK-Studio/gortal/config"
	"github.com/TNK-Studio/gortal/core/jump"
	"github.com/TNK-Studio/gortal/core/sshd"
	"github.com/TNK-Studio/gortal/utils"
	"github.com/TNK-Studio/gortal/utils/logger"
	myssh "github.com/elfgzp/ssh"
	"github.com/go-ldap/ldap"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"time"
)

var (
	// Port port
	Port *int

	hostKeyFile *string
)

func init() {
	Port = flag.Int("p", 2222, "Port")
	hostKeyFile = flag.String("hk", ".ssh/id_rsa", "Host key file")
}

func passwordAuth(ctx myssh.Context, pass string) bool {
	config.Conf.ReadFrom(*config.ConfPath)
	var success bool
	if (len(*config.Conf.Users)) < 1 {
		success = (pass == "newuser")
	} else {
		l, err := ldap.Dial("tcp", config.Conf.LDAP.URI)
		if err != nil {
			fmt.Println("连接失败", err)
			return false
		}
		sdn := fmt.Sprintf(config.Conf.LDAP.FDN, ctx.User())
		err = l.Bind(sdn, pass)
		if err != nil {
			fmt.Println("管理员认证失败", err)
			success = jump.VarifyUser(ctx, pass)

		} else {
			success = true
			fmt.Println("succcess")
		}
	}
	if !success {
		time.Sleep(time.Second * 3)
	}
	return success
}

func publickKeyAuth(ctx myssh.Context, key myssh.PublicKey) bool {
	var pub string

	config.Conf.ReadFrom(*config.ConfPath)
	username := ctx.User()
	for _, user := range *config.Conf.Users {
		if user.Username == username {
			pub = user.PublicKey
		}
	}
	decodeBytes, _ := base64.StdEncoding.DecodeString(pub)
	allowed, _, _, _, _ := myssh.ParseAuthorizedKey(decodeBytes)

	return myssh.KeysEqual(key, allowed)
}

func sessionHandler(sess *myssh.Session) {
	defer func() {
		(*sess).Close()
	}()

	rawCmd := (*sess).RawCommand()
	cmd, args, err := sshd.ParseRawCommand(rawCmd)
	if err != nil {
		sshd.ErrorInfo(err, sess)
		return
	}

	switch cmd {
	case "scp":
		sshd.ExecuteSCP(args, sess)
	default:
		sshHandler(sess)
	}
}

func sshHandler(sess *myssh.Session) {
	jps := jump.Service{}
	jps.Run(sess)
}

func scpHandler(args []string, sess *myssh.Session) {
	sshd.ExecuteSCP(args, sess)
}

func main() {
	flag.Parse()

	if !utils.FileExited(*hostKeyFile) {
		sshd.GenKey(*hostKeyFile)
	}

	myssh.Handle(func(sess myssh.Session) {
		defer func() {
			if e, ok := recover().(error); ok {
				logger.Logger.Panic(e)
			}
		}()
		sessionHandler(&sess)
	})

	log.Printf("starting ssh server on port %d...\n", *Port)
	log.Fatal(myssh.ListenAndServe(
		fmt.Sprintf(":%d", *Port),
		nil,
		myssh.PasswordAuth(passwordAuth),
		myssh.PublicKeyAuth(publickKeyAuth),
		func(server *myssh.Server) error {
			var cc myssh.PublicKeyHandler

			cc = func(ctx myssh.Context, key myssh.PublicKey) bool {
				authorizedKeysMap := map[string]bool{}
				authorizedKeysBytes, err := os.ReadFile(".ssh/authorized_keys")
				if err != nil {
					log.Fatalf("Failed to load authorized_keys, err: %v", err)
				}
				for len(authorizedKeysBytes) > 0 {
					pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
					if err != nil {
						log.Fatal(err)
					}

					authorizedKeysMap[string(pubKey.Marshal())] = true
					authorizedKeysBytes = rest
				}
				for len(authorizedKeysBytes) > 0 {
					pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
					if err != nil {
						log.Fatal(err)
					}

					authorizedKeysMap[string(pubKey.Marshal())] = true
					authorizedKeysBytes = rest
				}
				if authorizedKeysMap[string(key.Marshal())] {
					return true
				}
				return false
			}
			server.PublicKeyHandler = cc
			return nil
		},
		myssh.HostKeyFile(utils.FilePath(*hostKeyFile)),
	),
	)
}
