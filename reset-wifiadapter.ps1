# Return network interface to a variable for future use
$interface = Get-NetAdapter | Where-Object InterfaceType -eq 71

# Remove the static default gateway
$interface | Remove-NetRoute -AddressFamily IPv4 -Confirm:$false

# Set interface to "Obtain an IP address automatically"
$interface | Set-NetIPInterface -Dhcp Enabled

# Set interface to "Obtain DNS server address automatically"
$interface | Set-DnsClientServerAddress -ResetServerAddresses
