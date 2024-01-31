# Read the contents of shellcode.txt
with open('shellcode.txt', 'r') as file:
    data = file.read()

# Extract the text within curly braces
start = data.find('{') + 1
end = data.find('}')
byte_array = data[start:end]

# Split the string on commas, remove '0x', strip spaces and newlines, and rejoin with commas
formatted_string = ','.join(byte.replace('0x', '').strip() for byte in byte_array.split(','))

# Create and write to string.txt
with open('string.txt', 'w') as file:
    file.write(f'"{formatted_string}"')