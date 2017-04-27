# How to install Flytrap

## Compiling and installing

Flytrap uses the GNU autotools and should build cleanly on most
up-to-date Linux and FreeBSD systems:

```
$ ./configure
$ make
$ sudo make install
```

When installing from a Git clone rather than a distribution tarball,
you will have to run the `autogen.sh` script first.

## Configuring and running

Instructions for configuring and running Flytrap on RHEL6, RHEL7 and
FreeBSD 10 and up are provided below.  The instructions for RHEL6 and
RHEL7 should work for the corresponding CentOS releases as well.
Other Linux and BSD flavors may require different scripts and
configuration files.

### Configuration

#### RHEL

Create `/etc/sysconfig/flytrap`, which must at a minimum define
`INTERFACE` to the network interface on which Flytrap should listen.
You may also want to define `CSVFILE` if you want to write traffic
data to a different location than the default `/var/log/flytrap.csv`,
and finally `OPTIONS` to set any other command-line options such as
inclusion or exclusion ranges; refer to the manual page for details.

```
INTERFACE=eth0
# CSVFILE=/var/log/flytrap/flytrap.csv
OPTIONS="-X 172.16.0.0/12"
```

#### FreeBSD

Create `/usr/local/etc/rc.conf.d/flytrap`, which must at a minimum
define `flytrap_interface` to the network interface on which Flytrap
should listen.  You may also want to define `flytrap_csvfile` if you
want to write traffic data to a different location than the default
`/var/log/flytrap.csv`, and finally `flytrap_flags` to set any other
command-line options such as inclusion or exclusion ranges; refer to
the manual page for details.

```
flytrap_interface=bge0
# flytrap_csvfile=/var/log/flytrap/flytrap.csv
flytrap_flags="-X 172.16.0.0/12"
```

### Startup

#### RHEL6 (init.d)

Install the init script:

```
$ sudo cp rc/flytrap.init /etc/rc.d/init.d/flytrap
```

Then enable and start the `flytrap` service:

```
$ sudo chkconfig flytrap on
$ sudo service flytrap start
```

#### RHEL7 (systemd)

Install the unit file:

```
$ sudo cp rc/flytrap.systemd /usr/lib/systemd/system/flytrap.service
```

Then enable and start the `flytrap` service:

```
$ sudo systemctl enable flytrap
$ sudo systemctl start flytrap
```

### FreeBSD

Install the init script:

```
$ sudo cp rc/flytrap.rc /usr/local/etc/rc.d/flytrap
```

Then enable and start the `flytrap` service:

```
$ echo flytrap_enable=yes | sudo tee -a /usr/local/etc/rc.conf.d/flytrap
$ sudo service flytrap start
```

### Traffic data

Flytrap can generate large amounts of traffic data in CSV format.  You
are strongly encouraged to set up a separate filesystem for the
Flytrap CSV files.  If you do, remember to set the modify the
configuration file (see above) and the logrotate or newsyslog
configuration (see below) to reflect the correct path.

#### RHEL

Set up rotation of the traffic data by installing the provided
logrotate configuration file:

```
$ sudo cp rc/flytrap.logrotate /etc/logrotate.d/
```

#### FreeBSD

Set up rotation of the traffic data by creating
`/usr/local/etc/newsyslog.conf.d/flytrap` with the following contents:

```
/var/log/flytrap.csv 640 28 * $D0 XB /var/run/flytrap.pid
```
