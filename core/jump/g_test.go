package jump

import (
	"github.com/TNK-Studio/gortal/passhs"
	"testing"
)

func TestPasswordHash(t *testing.T) {
	got, _ := passhs.PasswordHash("yehwang1024")
	println(got)
	verify := passhs.PasswordVerify("yehwang1024", "$2a$10$touaWlM9cYYtrdi5CbPJ8ePKrnHFucVjetkNA7/wbOQXod2twWryW")
	println(verify)

}
