package golm

//
// import (
// 	"encoding/json"
// 	"errors"
// )
//
// type User struct {
// 	ID     string
// 	Device *Device
// }
//
// func NewUser(id string) *User {
// 	return &User{
// 		ID:     id,
// 		Device: nil,
// 	}
// }
//
// func (u *User) CreateDevice(id string) error {
// 	if u.Device != nil {
// 		return errors.New("device already exists")
// 	}
//
// 	var err error
// 	u.Device, err = NewDevice(id)
//
// 	return err
// }
//
// type curveContainer struct {
// 	Curves map[string]string `json:"curve25519"`
// }
//
// type keyContainer struct {
// 	Key        string                       `json:"key"`
// 	Signatures map[string]map[string]string `json:"signatures"`
// }
//
// type oneTimeKeysContainer struct {
// 	OneTimeKeys map[string]*keyContainer `json:"one_time_keys"`
// }
//
// func (u *User) SignAllOneTimeKeys() (string, error) {
// 	container := &curveContainer{}
// 	json.Unmarshal([]byte(u.Device.Account.OneTimeKeys()), container)
//
// 	signedKeys := &oneTimeKeysContainer{
// 		OneTimeKeys: make(map[string]*keyContainer),
// 	}
//
// 	for keyID, key := range container.Curves {
// 		signature, err := u.Device.Account.Sign(key)
// 		if err != nil {
// 			return "", err
// 		}
//
// 		signedKeys.OneTimeKeys["signed_curve25519:"+keyID] = &keyContainer{
// 			Key: key,
// 			Signatures: map[string]map[string]string{
// 				u.ID: map[string]string{
// 					"ed25519:" + u.Device.ID: signature,
// 				},
// 			},
// 		}
// 	}
//
// 	signedKeysJSON, err := json.MarshalIndent(signedKeys, "", "  ")
//
// 	return string(signedKeysJSON), err
// }
