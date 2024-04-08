package ntopng

type NtopngJsonDriver struct {
}

// Prepare the driver (flag init)
func (nj *NtopngJsonDriver) Prepare() error {

}

// Initialize the driver (parse flags, etc)
func (nj *NtopngJsonDriver) Init() error {

}

// Send a message to ntopng
func (nj *NtopngJsonDriver) Format(data interface{}) ([]byte, []byte, error) {

}
