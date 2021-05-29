# keepassxc_proxy_client

A small library as well as CLI tool to fetch information from a running keepassxc instance.

## CLI

See `keepassxc_proxy_client --help` for usage.

## Library

You can use it like this:
```python
import keepassxc_proxy_client
import keepassxc_proxy_client.protocol

connection = keepassxc_proxy_client.protocol.Connection()
connection.connect()
print(connection.get_databasehash())
# This will open a keepassxc dialogue
print(connection.associate())
print(connection.test_associate())
print(connection.dump_associate())
print(connection.get_logins("https://github.com"))
```
Please always use a URL with http or https for retreiving logins, otherwise no logins will be found.
You can use `connection.get_logins("https://github.com")` when you actually stored URL just as "github.com" 
within KeepassXC. This will work. 
However it won't work using get_logins("github.com") even if you have stored URL as "github.com".

To connect and retreive logins from KeepassXC Browser integration has to be enabled in settings. 
Checkboxes for different Browser don't need to be checked. Enabled browser integration is enough 
for keepassxc_proxy_client to work.


If you want to dump and later read in the associate information you can do this
as follows:

```python
import keepassxc_proxy_client
import keepassxc_proxy_client.protocol

connection = keepassxc_proxy_client.protocol.Connection()
connection.connect()
connection.associate()
name, public_key = connection.dump_associate()
print("Got connection named '", name, "' with key", public_key)
# save it and read it in again for later

#Later usage

connection = keepassxc_proxy_client.protocol.Connection()
connection.connect()
connection.load_associate(name, public_key)
print(connection.test_associate())
```

It is recommended to store the private key in a secure location since it basically acts
as a key file to all your passwords that are associated with a URL, since get_logins() can only fetch
passwords that are associated with one.
