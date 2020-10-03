import keepassxc_proxy_client
import keepassxc_proxy_client.protocol

connection = keepassxc_proxy_client.protocol.Connection()
connection.connect()
print(connection.get_databasehash())
print(connection.associate())
print(connection.test_associate())
print(connection.dump_associate())
print(connection.get_logins("https://github.com"))
