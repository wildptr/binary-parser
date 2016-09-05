parser = require(arg[1])
file = io.open(arg[2], 'rb')
parser.parse(file):print()
