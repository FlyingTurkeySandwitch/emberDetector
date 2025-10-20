import lief

# Load the executable
binary = lief.parse("WhoIs/whois64.exe")
print(binary)
