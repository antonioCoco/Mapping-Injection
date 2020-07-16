import sys

def generate_byte_file_string(byte_arr):
    return '{' + ",".join('0x{:02x}'.format(x) for x in byte_arr) + '}'
    
with open(sys.argv[1], 'rb') as bin_file:
    byte_arr_file = bytearray(bin_file.read())
    byte_file_string = generate_byte_file_string(byte_arr_file)
    print 'char %s[] = %s;' % (sys.argv[2], byte_file_string)