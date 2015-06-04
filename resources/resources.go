package resources

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/thrisp/flotilla"
)

var SecurityAsset *flotilla.AssetFS = &flotilla.AssetFS{Asset, AssetDir, AssetNames, ""}

func bindata_read(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindata_file_info struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindata_file_info) Name() string {
	return fi.name
}
func (fi bindata_file_info) Size() int64 {
	return fi.size
}
func (fi bindata_file_info) Mode() os.FileMode {
	return fi.mode
}
func (fi bindata_file_info) ModTime() time.Time {
	return fi.modTime
}
func (fi bindata_file_info) IsDir() bool {
	return false
}
func (fi bindata_file_info) Sys() interface{} {
	return nil
}

var _templates_change_html = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xaa\xae\x56\x48\xad\x28\x49\xcd\x4b\x29\x56\x50\x2a\x4e\x4d\x2e\x2d\xca\x2c\xa9\xd4\xcb\x28\xc9\xcd\x51\x52\xa8\xad\xe5\x02\xca\xa6\xa4\xa6\x65\xe6\xa5\x2a\x28\x15\xe5\xe7\x97\x80\xc5\x14\x80\x20\xd8\xd5\x39\x34\xc8\x33\x24\x52\xc1\xd9\xc3\xd1\xcf\xdd\x55\x21\xc0\x31\x38\x38\xdc\x3f\xc8\x05\x2c\x09\xd4\xa4\xe7\x11\xe2\xeb\xa3\xa0\x94\x9c\x91\x98\x97\x9e\x1a\x5f\x90\x58\x5c\x5c\x9e\x5f\x94\x12\x9f\x96\x5f\x94\x0b\x33\x17\x68\x25\x88\x05\x08\x00\x00\xff\xff\x55\x0e\x4f\x2d\x80\x00\x00\x00")

func templates_change_html_bytes() ([]byte, error) {
	return bindata_read(
		_templates_change_html,
		"templates/change.html",
	)
}

func templates_change_html() (*asset, error) {
	bytes, err := templates_change_html_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "templates/change.html", size: 128, mode: os.FileMode(436), modTime: time.Unix(1431526461, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _templates_confirm_user_html = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\x01\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00")

func templates_confirm_user_html_bytes() ([]byte, error) {
	return bindata_read(
		_templates_confirm_user_html,
		"templates/confirm_user.html",
	)
}

func templates_confirm_user_html() (*asset, error) {
	bytes, err := templates_confirm_user_html_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "templates/confirm_user.html", size: 0, mode: os.FileMode(436), modTime: time.Unix(1432335953, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _templates_login_html = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xaa\xae\x56\x48\xad\x28\x49\xcd\x4b\x29\x56\x50\x2a\x4e\x4d\x2e\x2d\xca\x2c\xa9\xd4\xcb\x28\xc9\xcd\x51\x52\xa8\xad\xe5\x02\xca\xa6\xa4\xa6\x65\xe6\xa5\x2a\x28\x15\xe5\xe7\x97\x80\xc5\x14\x80\x20\xd8\xd5\x39\x34\xc8\x33\x24\x52\xc1\xc7\xdf\xdd\xd3\x4f\x21\xc4\xd5\x37\xc0\xc7\x31\xc4\x15\x2c\x07\xd4\xa3\xe7\x11\xe2\xeb\xa3\xa0\x94\x93\x9f\x9e\x99\x17\x9f\x96\x5f\x94\x0b\x33\x0c\x68\x0f\x88\x05\x08\x00\x00\xff\xff\x50\xaa\x5c\x68\x75\x00\x00\x00")

func templates_login_html_bytes() ([]byte, error) {
	return bindata_read(
		_templates_login_html,
		"templates/login.html",
	)
}

func templates_login_html() (*asset, error) {
	bytes, err := templates_login_html_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "templates/login.html", size: 117, mode: os.FileMode(436), modTime: time.Unix(1431525862, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _templates_passwordless_login_html = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xaa\xae\x56\x48\xad\x28\x49\xcd\x4b\x29\x56\x50\x2a\x4e\x4d\x2e\x2d\xca\x2c\xa9\xd4\xcb\x28\xc9\xcd\x51\x52\xa8\xad\xe5\x02\xca\xa6\xa4\xa6\x65\xe6\xa5\x2a\x28\x15\xe5\xe7\x97\x80\xc5\x14\x80\x20\xd8\xd5\x39\x34\xc8\x33\x24\x52\x21\xc0\x31\x38\x38\xdc\x3f\xc8\xc5\xc7\x35\x38\x38\xde\xc7\xdf\xdd\xd3\x2f\xde\xcd\x3f\xc8\x17\xac\x08\xa8\x59\xcf\x23\xc4\xd7\x47\x41\xa9\x20\xb1\xb8\xb8\x3c\xbf\x28\x25\x27\xb5\xb8\x38\x3e\x27\x3f\x3d\x33\x2f\x3e\x2d\xbf\x28\x17\x66\x05\xd0\x76\x10\x0b\x10\x00\x00\xff\xff\x91\xbc\x22\x6d\x8b\x00\x00\x00")

func templates_passwordless_login_html_bytes() ([]byte, error) {
	return bindata_read(
		_templates_passwordless_login_html,
		"templates/passwordless_login.html",
	)
}

func templates_passwordless_login_html() (*asset, error) {
	bytes, err := templates_passwordless_login_html_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "templates/passwordless_login.html", size: 139, mode: os.FileMode(436), modTime: time.Unix(1432227196, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _templates_register_html = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xaa\xae\x56\x48\xad\x28\x49\xcd\x4b\x29\x56\x50\x2a\x4e\x4d\x2e\x2d\xca\x2c\xa9\xd4\xcb\x28\xc9\xcd\x51\x52\xa8\xad\xe5\x02\xca\xa6\xa4\xa6\x65\xe6\xa5\x2a\x28\x15\xe5\xe7\x97\x80\xc5\x14\x80\x20\xd8\xd5\x39\x34\xc8\x33\x24\x52\x21\xc8\xd5\xdd\x33\x38\xc4\x35\x48\x21\x34\xd8\x35\x08\x2c\x05\xd4\xa2\xe7\x11\xe2\xeb\x03\xd4\x91\x9a\x9e\x59\x5c\x92\x5a\x14\x9f\x96\x5f\x94\x0b\x33\x0e\x68\x13\x88\x05\x08\x00\x00\xff\xff\x3c\xd4\x9f\x3a\x77\x00\x00\x00")

func templates_register_html_bytes() ([]byte, error) {
	return bindata_read(
		_templates_register_html,
		"templates/register.html",
	)
}

func templates_register_html() (*asset, error) {
	bytes, err := templates_register_html_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "templates/register.html", size: 119, mode: os.FileMode(436), modTime: time.Unix(1431526487, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _templates_reset_html = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xaa\xae\x56\x48\xad\x28\x49\xcd\x4b\x29\x56\x50\x2a\x4e\x4d\x2e\x2d\xca\x2c\xa9\xd4\xcb\x28\xc9\xcd\x51\x52\xa8\xad\xe5\x02\xca\xa6\xa4\xa6\x65\xe6\xa5\x2a\x28\x15\xe5\xe7\x97\x80\xc5\x14\x80\x20\xd8\xd5\x39\x34\xc8\x33\x24\x52\x21\xc8\x35\xd8\x35\x44\x21\xc0\x31\x38\x38\xdc\x3f\xc8\x05\x2c\x07\xd4\xa3\xe7\x11\xe2\xeb\x03\xd4\x92\x5a\x9c\x5a\x12\x5f\x90\x58\x5c\x5c\x9e\x5f\x94\x12\x9f\x96\x5f\x94\x0b\x33\x15\x68\x21\x88\x05\x08\x00\x00\xff\xff\xdd\xff\xa6\x2a\x7e\x00\x00\x00")

func templates_reset_html_bytes() ([]byte, error) {
	return bindata_read(
		_templates_reset_html,
		"templates/reset.html",
	)
}

func templates_reset_html() (*asset, error) {
	bytes, err := templates_reset_html_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "templates/reset.html", size: 126, mode: os.FileMode(436), modTime: time.Unix(1431526510, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _templates_security_html = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xb2\x51\x74\xf1\x77\x0e\x89\x0c\x70\x55\xc8\x28\xc9\xcd\xb1\xe3\xb2\x81\x51\xa9\x89\x29\x76\x36\xfa\x60\x8a\xcb\x26\x29\x3f\xa5\xd2\x8e\x4b\x01\x08\x6c\x8a\x4b\x2a\x73\x52\x81\x32\x10\x1a\x2c\x56\x5d\xad\x50\x92\x9a\x5b\x90\x93\x58\x92\xaa\xa0\x54\x94\x9f\x5f\xa2\xa4\x50\x5b\xcb\x65\xa3\x0f\xd1\x05\x08\x00\x00\xff\xff\x61\x93\x94\xac\x62\x00\x00\x00")

func templates_security_html_bytes() ([]byte, error) {
	return bindata_read(
		_templates_security_html,
		"templates/security.html",
	)
}

func templates_security_html() (*asset, error) {
	bytes, err := templates_security_html_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "templates/security.html", size: 98, mode: os.FileMode(436), modTime: time.Unix(1431526295, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _templates_send_confirm_html = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xaa\xae\x56\x48\xad\x28\x49\xcd\x4b\x29\x56\x50\x2a\x4e\x4d\x2e\x2d\xca\x2c\xa9\xd4\xcb\x28\xc9\xcd\x51\x52\xa8\xad\xe5\x02\xca\xa6\xa4\xa6\x65\xe6\xa5\x2a\x28\x15\xe5\xe7\x97\x80\xc5\x14\x80\x20\xd8\xd5\x39\x34\xc8\x33\x24\x12\xc8\xf0\x73\x51\x70\xf6\xf7\x73\xf3\x0c\xf2\x75\x0c\xf1\xf4\xf7\x03\x4b\x03\xb5\xe9\x79\x84\xf8\xfa\x28\x28\x25\xe7\xe7\xa5\x65\x16\xe5\x26\x96\x64\xe6\xe7\xc5\xa7\xe5\x17\xe5\xc2\x8c\x05\xda\x08\x62\x01\x02\x00\x00\xff\xff\x0b\xdd\xef\x6b\x7f\x00\x00\x00")

func templates_send_confirm_html_bytes() ([]byte, error) {
	return bindata_read(
		_templates_send_confirm_html,
		"templates/send_confirm.html",
	)
}

func templates_send_confirm_html() (*asset, error) {
	bytes, err := templates_send_confirm_html_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "templates/send_confirm.html", size: 127, mode: os.FileMode(436), modTime: time.Unix(1431526409, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _templates_send_reset_html = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xaa\xae\x56\x48\xad\x28\x49\xcd\x4b\x29\x56\x50\x2a\x4e\x4d\x2e\x2d\xca\x2c\xa9\xd4\xcb\x28\xc9\xcd\x51\x52\xa8\xad\xe5\x02\xca\xa6\xa4\xa6\x65\xe6\xa5\x2a\x28\x15\xe5\xe7\x97\x80\xc5\x14\x80\x20\xd8\xd5\x39\x34\xc8\x33\x24\x12\xc8\xf0\x73\x51\x08\x72\x0d\x76\x0d\x51\x08\x70\x0c\x0e\x0e\xf7\x0f\x72\x01\x2b\x00\x6a\xd4\xf3\x08\xf1\xf5\x01\x19\x9a\x97\x12\x5f\x94\x5a\x9c\x5a\x12\x9f\x96\x5f\x94\x0b\x33\x16\x28\x0a\x62\x01\x02\x00\x00\xff\xff\xee\x4a\x44\xda\x7f\x00\x00\x00")

func templates_send_reset_html_bytes() ([]byte, error) {
	return bindata_read(
		_templates_send_reset_html,
		"templates/send_reset.html",
	)
}

func templates_send_reset_html() (*asset, error) {
	bytes, err := templates_send_reset_html_bytes()
	if err != nil {
		return nil, err
	}

	info := bindata_file_info{name: "templates/send_reset.html", size: 127, mode: os.FileMode(436), modTime: time.Unix(1433160383, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"templates/change.html":             templates_change_html,
	"templates/confirm_user.html":       templates_confirm_user_html,
	"templates/login.html":              templates_login_html,
	"templates/passwordless_login.html": templates_passwordless_login_html,
	"templates/register.html":           templates_register_html,
	"templates/reset.html":              templates_reset_html,
	"templates/security.html":           templates_security_html,
	"templates/send_confirm.html":       templates_send_confirm_html,
	"templates/send_reset.html":         templates_send_reset_html,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for name := range node.Children {
		rv = append(rv, name)
	}
	return rv, nil
}

type _bintree_t struct {
	Func     func() (*asset, error)
	Children map[string]*_bintree_t
}

var _bintree = &_bintree_t{nil, map[string]*_bintree_t{
	"templates": &_bintree_t{nil, map[string]*_bintree_t{
		"change.html":             &_bintree_t{templates_change_html, map[string]*_bintree_t{}},
		"confirm_user.html":       &_bintree_t{templates_confirm_user_html, map[string]*_bintree_t{}},
		"login.html":              &_bintree_t{templates_login_html, map[string]*_bintree_t{}},
		"passwordless_login.html": &_bintree_t{templates_passwordless_login_html, map[string]*_bintree_t{}},
		"register.html":           &_bintree_t{templates_register_html, map[string]*_bintree_t{}},
		"reset.html":              &_bintree_t{templates_reset_html, map[string]*_bintree_t{}},
		"security.html":           &_bintree_t{templates_security_html, map[string]*_bintree_t{}},
		"send_confirm.html":       &_bintree_t{templates_send_confirm_html, map[string]*_bintree_t{}},
		"send_reset.html":         &_bintree_t{templates_send_reset_html, map[string]*_bintree_t{}},
	}},
}}

// Restore an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, path.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// Restore assets under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	if err != nil { // File
		return RestoreAsset(dir, name)
	} else { // Dir
		for _, child := range children {
			err = RestoreAssets(dir, path.Join(name, child))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
