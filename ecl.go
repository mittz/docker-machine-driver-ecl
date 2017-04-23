package ecl

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/mcnutils"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
)

type Driver struct {
	*drivers.BaseDriver
	AuthUrl          string
	ActiveTimeout    int
	Insecure         bool
	CaCert           string
	DomainID         string
	DomainName       string
	Username         string
	Password         string
	TenantName       string
	TenantId         string
	AvailabilityZone string
	EndpointType     string
	MachineId        string
	FlavorName       string
	FlavorId         string
	ImageName        string
	ImageId          string
	KeyPairName      string
	NetworkName      string
	NetworkId        string
	UserData         []byte
	PrivateKeyFile   string
	ComputeNetwork   bool
	IpVersion        int
	client           Client
}

const (
	defaultSSHUser       = "root"
	defaultSSHPort       = 22
	defaultActiveTimeout = 200
	defaultDomainID      = "default"
	defaultEndpointType  = "publicURL"
	fixedIPVersion       = 4
)

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			EnvVar: "ECL_AUTH_URL",
			Name:   "ecl-auth-url",
			Usage:  "ecl authentication URL",
			Value:  "",
		},
		mcnflag.BoolFlag{
			EnvVar: "ECL_INSECURE",
			Name:   "ecl-insecure",
			Usage:  "Disable TLS credential checking.",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_CACERT",
			Name:   "ecl-cacert",
			Usage:  "CA certificate bundle to verify against",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_DOMAIN_ID",
			Name:   "ecl-domain-id",
			Usage:  "ecl domain ID (identity v3 only) default value is 'default'.",
			Value:  defaultDomainID,
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_DOMAIN_NAME",
			Name:   "ecl-domain-name",
			Usage:  "ecl domain name (identity v3 only)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_USERNAME",
			Name:   "ecl-username",
			Usage:  "ecl username",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_PASSWORD",
			Name:   "ecl-password",
			Usage:  "ecl password",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_TENANT_NAME",
			Name:   "ecl-tenant-name",
			Usage:  "ecl tenant name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_TENANT_ID",
			Name:   "ecl-tenant-id",
			Usage:  "ecl tenant id",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_AVAILABILITY_ZONE",
			Name:   "ecl-availability-zone",
			Usage:  "ecl availability zone",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_ENDPOINT_TYPE",
			Name:   "ecl-endpoint-type",
			Usage:  "ecl endpoint type (adminURL, internalURL or publicURL) default value is 'publicURL'",
			Value:  defaultEndpointType,
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_FLAVOR_ID",
			Name:   "ecl-flavor-id",
			Usage:  "ecl flavor id to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_FLAVOR_NAME",
			Name:   "ecl-flavor-name",
			Usage:  "ecl flavor name to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_IMAGE_ID",
			Name:   "ecl-image-id",
			Usage:  "ecl image id to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_IMAGE_NAME",
			Name:   "ecl-image-name",
			Usage:  "ecl image name to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_KEYPAIR_NAME",
			Name:   "ecl-keypair-name",
			Usage:  "ecl keypair to use to SSH to the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_NETWORK_ID",
			Name:   "ecl-net-id",
			Usage:  "ecl network id the machine will be connected on",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_PRIVATE_KEY_FILE",
			Name:   "ecl-private-key-file",
			Usage:  "Private keyfile to use for SSH (absolute path)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_USER_DATA_FILE",
			Name:   "ecl-user-data-file",
			Usage:  "File containing an ecl userdata script",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_NETWORK_NAME",
			Name:   "ecl-net-name",
			Usage:  "ecl network name the machine will be connected on",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "ECL_SSH_USER",
			Name:   "ecl-ssh-user",
			Usage:  "ecl SSH user",
			Value:  defaultSSHUser,
		},
		mcnflag.IntFlag{
			EnvVar: "ECL_SSH_PORT",
			Name:   "ecl-ssh-port",
			Usage:  "ecl SSH port",
			Value:  defaultSSHPort,
		},
		mcnflag.IntFlag{
			EnvVar: "ECL_ACTIVE_TIMEOUT",
			Name:   "ecl-active-timeout",
			Usage:  "ecl active timeout",
			Value:  defaultActiveTimeout,
		},
	}
}

func NewDriver(hostName, storePath string) drivers.Driver {
	return NewDerivedDriver(hostName, storePath)
}

func NewDerivedDriver(hostName, storePath string) *Driver {
	return &Driver{
		client:        &GenericClient{},
		ActiveTimeout: defaultActiveTimeout,
		BaseDriver: &drivers.BaseDriver{
			SSHUser:     defaultSSHUser,
			SSHPort:     defaultSSHPort,
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

func (d *Driver) SetClient(client Client) {
	d.client = client
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return "ecl"
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.AuthUrl = flags.String("ecl-auth-url")
	d.ActiveTimeout = flags.Int("ecl-active-timeout")
	d.Insecure = flags.Bool("ecl-insecure")
	d.CaCert = flags.String("ecl-cacert")
	d.DomainID = flags.String("ecl-domain-id")
	d.DomainName = flags.String("ecl-domain-name")
	d.Username = flags.String("ecl-username")
	d.Password = flags.String("ecl-password")
	d.TenantName = flags.String("ecl-tenant-name")
	d.TenantId = flags.String("ecl-tenant-id")
	d.AvailabilityZone = flags.String("ecl-availability-zone")
	d.EndpointType = flags.String("ecl-endpoint-type")
	d.FlavorId = flags.String("ecl-flavor-id")
	d.FlavorName = flags.String("ecl-flavor-name")
	d.ImageId = flags.String("ecl-image-id")
	d.ImageName = flags.String("ecl-image-name")
	d.NetworkId = flags.String("ecl-net-id")
	d.NetworkName = flags.String("ecl-net-name")
	d.IpVersion = fixedIPVersion
	d.SSHUser = flags.String("ecl-ssh-user")
	d.SSHPort = flags.Int("ecl-ssh-port")
	d.KeyPairName = flags.String("ecl-keypair-name")
	d.PrivateKeyFile = flags.String("ecl-private-key-file")

	if flags.String("ecl-user-data-file") != "" {
		userData, err := ioutil.ReadFile(flags.String("ecl-user-data-file"))
		if err == nil {
			d.UserData = userData
		} else {
			return err
		}
	}

	d.SetSwarmConfigFromFlags(flags)

	return d.checkConfig()
}

func (d *Driver) GetURL() (string, error) {
	if err := drivers.MustBeRunning(d); err != nil {
		return "", err
	}

	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", nil
	}

	return fmt.Sprintf("tcp://%s", net.JoinHostPort(ip, "2376")), nil
}

func (d *Driver) GetIP() (string, error) {
	if d.IPAddress != "" {
		return d.IPAddress, nil
	}

	log.Debug("Looking for the IP address...", map[string]string{"MachineId": d.MachineId})

	if err := d.initCompute(); err != nil {
		return "", err
	}

	addressType := Fixed

	// Looking for the IP address in a retry loop to deal with ecl latency
	for retryCount := 0; retryCount < 200; retryCount++ {
		addresses, err := d.client.GetInstanceIPAddresses(d)
		if err != nil {
			return "", err
		}
		for _, a := range addresses {
			if a.AddressType == addressType && a.Version == d.IpVersion {
				return a.Address, nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return "", fmt.Errorf("No IP found for the machine")
}

func (d *Driver) GetState() (state.State, error) {
	log.Debug("Get status for ecl instance...", map[string]string{"MachineId": d.MachineId})
	if err := d.initCompute(); err != nil {
		return state.None, err
	}

	s, err := d.client.GetInstanceState(d)
	if err != nil {
		return state.None, err
	}

	log.Debug("State for ecl instance", map[string]string{
		"MachineId": d.MachineId,
		"State":     s,
	})

	switch s {
	case "ACTIVE":
		return state.Running, nil
	case "PAUSED":
		return state.Paused, nil
	case "SUSPENDED":
		return state.Saved, nil
	case "SHUTOFF":
		return state.Stopped, nil
	case "BUILDING":
		return state.Starting, nil
	case "ERROR":
		return state.Error, nil
	}
	return state.None, nil
}

func (d *Driver) Create() error {
	if err := d.resolveIds(); err != nil {
		return err
	}
	if d.KeyPairName != "" {
		if err := d.loadSSHKey(); err != nil {
			return err
		}
	} else {
		d.KeyPairName = fmt.Sprintf("%s-%s", d.MachineName, mcnutils.GenerateRandomID())
		if err := d.createSSHKey(); err != nil {
			return err
		}
	}
	if err := d.createMachine(); err != nil {
		return err
	}
	if err := d.waitForInstanceActive(); err != nil {
		return err
	}
	if err := d.lookForIPAddress(); err != nil {
		return err
	}
	return nil
}

func (d *Driver) Start() error {
	if err := d.initCompute(); err != nil {
		return err
	}

	return d.client.StartInstance(d)
}

func (d *Driver) Stop() error {
	if err := d.initCompute(); err != nil {
		return err
	}

	return d.client.StopInstance(d)
}

func (d *Driver) Restart() error {
	if err := d.initCompute(); err != nil {
		return err
	}

	return d.client.RestartInstance(d)
}

func (d *Driver) Kill() error {
	return d.Stop()
}

func (d *Driver) Remove() error {
	log.Debug("deleting instance...", map[string]string{"MachineId": d.MachineId})
	log.Info("Deleting ecl instance...")
	if err := d.initCompute(); err != nil {
		return err
	}
	if err := d.client.DeleteInstance(d); err != nil {
		return err
	}
	log.Debug("deleting key pair...", map[string]string{"Name": d.KeyPairName})
	// TODO (fsoppelsa) maybe we want to check this, in case of shared keypairs, before removal
	if err := d.client.DeleteKeyPair(d, d.KeyPairName); err != nil {
		return err
	}
	return nil
}

const (
	errorMandatoryEnvOrOption    string = "%s must be specified either using the environment variable %s or the CLI option %s"
	errorMandatoryOption         string = "%s must be specified using the CLI option %s"
	errorExclusiveOptions        string = "Either %s or %s must be specified, not both"
	errorBothOptions             string = "Both %s and %s must be specified"
	errorMandatoryTenantNameOrID string = "Tenant id or name must be provided either using one of the environment variables ECL_TENANT_ID and ECL_TENANT_NAME or one of the CLI options --ecl-tenant-id and --ecl-tenant-name"
	errorWrongEndpointType       string = "Endpoint type must be 'publicURL', 'adminURL' or 'internalURL'"
	errorUnknownFlavorName       string = "Unable to find flavor named %s"
	errorUnknownImageName        string = "Unable to find image named %s"
	errorUnknownNetworkName      string = "Unable to find network named %s"
	errorUnknownTenantName       string = "Unable to find tenant named %s"
)

func (d *Driver) checkConfig() error {
	if d.AuthUrl == "" {
		return fmt.Errorf(errorMandatoryEnvOrOption, "Authentication URL", "ECL_AUTH_URL", "--ecl-auth-url")
	}
	if d.Username == "" {
		return fmt.Errorf(errorMandatoryEnvOrOption, "Username", "ECL_USERNAME", "--ecl-username")
	}
	if d.Password == "" {
		return fmt.Errorf(errorMandatoryEnvOrOption, "Password", "ECL_PASSWORD", "--ecl-password")
	}
	if d.TenantName == "" && d.TenantId == "" {
		return fmt.Errorf(errorMandatoryTenantNameOrID)
	}

	if d.FlavorName == "" && d.FlavorId == "" {
		return fmt.Errorf(errorMandatoryOption, "Flavor name or Flavor id", "--ecl-flavor-name or --ecl-flavor-id")
	}
	if d.FlavorName != "" && d.FlavorId != "" {
		return fmt.Errorf(errorExclusiveOptions, "Flavor name", "Flavor id")
	}

	if d.ImageName == "" && d.ImageId == "" {
		return fmt.Errorf(errorMandatoryOption, "Image name or Image id", "--ecl-image-name or --ecl-image-id")
	}
	if d.ImageName != "" && d.ImageId != "" {
		return fmt.Errorf(errorExclusiveOptions, "Image name", "Image id")
	}

	if d.NetworkName != "" && d.NetworkId != "" {
		return fmt.Errorf(errorExclusiveOptions, "Network name", "Network id")
	}
	if d.EndpointType != "" && (d.EndpointType != "publicURL" && d.EndpointType != "adminURL" && d.EndpointType != "internalURL") {
		return fmt.Errorf(errorWrongEndpointType)
	}
	if (d.KeyPairName != "" && d.PrivateKeyFile == "") || (d.KeyPairName == "" && d.PrivateKeyFile != "") {
		return fmt.Errorf(errorBothOptions, "KeyPairName", "PrivateKeyFile")
	}
	return nil
}

func (d *Driver) resolveIds() error {
	if d.NetworkName != "" && !d.ComputeNetwork {
		if err := d.initNetwork(); err != nil {
			return err
		}

		networkID, err := d.client.GetNetworkID(d)

		if err != nil {
			return err
		}

		if networkID == "" {
			return fmt.Errorf(errorUnknownNetworkName, d.NetworkName)
		}

		d.NetworkId = networkID
		log.Debug("Found network id using its name", map[string]string{
			"Name": d.NetworkName,
			"ID":   d.NetworkId,
		})
	}

	if d.FlavorName != "" {
		if err := d.initCompute(); err != nil {
			return err
		}
		flavorID, err := d.client.GetFlavorID(d)

		if err != nil {
			return err
		}

		if flavorID == "" {
			return fmt.Errorf(errorUnknownFlavorName, d.FlavorName)
		}

		d.FlavorId = flavorID
		log.Debug("Found flavor id using its name", map[string]string{
			"Name": d.FlavorName,
			"ID":   d.FlavorId,
		})
	}

	if d.ImageName != "" {
		if err := d.initCompute(); err != nil {
			return err
		}
		imageID, err := d.client.GetImageID(d)

		if err != nil {
			return err
		}

		if imageID == "" {
			return fmt.Errorf(errorUnknownImageName, d.ImageName)
		}

		d.ImageId = imageID
		log.Debug("Found image id using its name", map[string]string{
			"Name": d.ImageName,
			"ID":   d.ImageId,
		})
	}

	if d.TenantName != "" && d.TenantId == "" {
		if err := d.initIdentity(); err != nil {
			return err
		}
		TenantId, err := d.client.GetTenantID(d)

		if err != nil {
			return err
		}

		if TenantId == "" {
			return fmt.Errorf(errorUnknownTenantName, d.TenantName)
		}

		d.TenantId = TenantId
		log.Debug("Found tenant id using its name", map[string]string{
			"Name": d.TenantName,
			"ID":   d.TenantId,
		})
	}

	return nil
}

func (d *Driver) initCompute() error {
	if err := d.client.Authenticate(d); err != nil {
		return err
	}
	if err := d.client.InitComputeClient(d); err != nil {
		return err
	}
	return nil
}

func (d *Driver) initIdentity() error {
	if err := d.client.Authenticate(d); err != nil {
		return err
	}
	if err := d.client.InitIdentityClient(d); err != nil {
		return err
	}
	return nil
}

func (d *Driver) initNetwork() error {
	if err := d.client.Authenticate(d); err != nil {
		return err
	}
	if err := d.client.InitNetworkClient(d); err != nil {
		return err
	}
	return nil
}

func (d *Driver) loadSSHKey() error {
	log.Debug("Loading Key Pair", d.KeyPairName)
	if err := d.initCompute(); err != nil {
		return err
	}
	log.Debug("Loading Private Key from", d.PrivateKeyFile)
	privateKey, err := ioutil.ReadFile(d.PrivateKeyFile)
	if err != nil {
		return err
	}
	publicKey, err := d.client.GetPublicKey(d.KeyPairName)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(d.privateSSHKeyPath(), privateKey, 0600); err != nil {
		return err
	}
	if err := ioutil.WriteFile(d.publicSSHKeyPath(), publicKey, 0600); err != nil {
		return err
	}

	return nil
}

func (d *Driver) createSSHKey() error {
	sanitizeKeyPairName(&d.KeyPairName)
	log.Debug("Creating Key Pair...", map[string]string{"Name": d.KeyPairName})
	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return err
	}
	publicKey, err := ioutil.ReadFile(d.publicSSHKeyPath())
	if err != nil {
		return err
	}

	if err := d.initCompute(); err != nil {
		return err
	}
	if err := d.client.CreateKeyPair(d, d.KeyPairName, string(publicKey)); err != nil {
		return err
	}
	return nil
}

func (d *Driver) createMachine() error {
	log.Debug("Creating ecl instance...", map[string]string{
		"FlavorId": d.FlavorId,
		"ImageId":  d.ImageId,
	})

	if err := d.initCompute(); err != nil {
		return err
	}
	instanceID, err := d.client.CreateInstance(d)
	if err != nil {
		return err
	}
	d.MachineId = instanceID
	return nil
}

func (d *Driver) waitForInstanceActive() error {
	log.Debug("Waiting for the ecl instance to be ACTIVE...", map[string]string{"MachineId": d.MachineId})
	if err := d.client.WaitForInstanceStatus(d, "ACTIVE"); err != nil {
		return err
	}
	return nil
}

func (d *Driver) lookForIPAddress() error {
	ip, err := d.GetIP()
	if err != nil {
		return err
	}
	d.IPAddress = ip
	log.Debug("IP address found", map[string]string{
		"IP":        ip,
		"MachineId": d.MachineId,
	})
	return nil
}

func (d *Driver) privateSSHKeyPath() string {
	return d.GetSSHKeyPath()
}

func (d *Driver) publicSSHKeyPath() string {
	return d.GetSSHKeyPath() + ".pub"
}

func sanitizeKeyPairName(s *string) {
	*s = strings.Replace(*s, ".", "_", -1)
}
