from f5_config_parser.ucs import UCS

input_files = ['f51.ucs',
               'f52.ucs']

collections = {}

for file in input_files:
    with UCS(file) as ucs:
        collection = ucs.load_collection()
        collections[file] = collection
        vlans = collection.filter(('net', 'vlan'))
        for vlan in vlans:
            vlan.config_lines[0] = vlan.config_lines[0].replace('/Common/', '/Partition_1/')
        ucs.write_back_collection(collection, file.replace('.ucs', '_updated.ucs'))

