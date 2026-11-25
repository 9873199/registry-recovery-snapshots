import struct
import registry_check as c
print('Registry log recovery - local synthetic evidence')
normal=c.run()
print('Normal chain:',[x.sequence for x in normal.report.selected_chain])
print('Recovered value:',normal.recovered.hive.root().value('RootV').data)
print('Short reads:',c.run(chunk=1).status.value)
print('Conflicting sequence:',c.run('conflict').status.value)
print('Missing predecessor:',c.run('missing').status.value)
print('Cell reference cycle trusted:',c.run('cycle').report.structure.trustworthy)
def rename_headers(files):
    for name in files:
        if '.LOG' in name:
            data=bytearray(files[name]);data[48:112]='SOFTWARE'.encode('utf-16-le').ljust(64,b'\x00');struct.pack_into('<I',data,508,c.checksum(data));files[name]=bytes(data)
    return files
changed=c.run(mutator=rename_headers)
print('Primary: NTUSER.DAT; log header: SOFTWARE')
print('Reported paired:',[x.paired for x in changed.report.logs])
print('Recovery status:',changed.status.value)
print('FAIL: contradictory log names still publish a recovered view')
print('All input hashes unchanged; caller streams remain open.')
raise SystemExit(1)
