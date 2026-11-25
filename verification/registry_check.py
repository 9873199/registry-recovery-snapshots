import io,json,pathlib,hashlib,struct
from dissect.regf.recovery import recover_hive,Evidence,RecoveryStatus
BASE=pathlib.Path(__file__).parent
DATA=BASE/'replay-source/tests/_data/recovery'
def checksum(b):
    value=0
    for i in range(0,508,4):value^=struct.unpack_from('<I',b,i)[0]
    return 1 if value==0 else 0xFFFFFFFE if value==0xFFFFFFFF else value
class Short(io.BytesIO):
    def __init__(self,data,chunk):super().__init__(data);self.chunk=chunk
    def read(self,n=-1):return super().read(self.chunk if n<0 else min(n,self.chunk))
def load(case):return {p.name:p.read_bytes() for p in (DATA/case).iterdir() if p.is_file()}
def run(case='minimal',order=('LOG2','LOG1'),chunk=None,mutator=None):
    files=load(case)
    if mutator:files=mutator(files)
    hashes={k:hashlib.sha256(v).hexdigest() for k,v in files.items()};streams={k:(io.BytesIO(v) if chunk is None else Short(v,chunk)) for k,v in files.items()};hive=streams['NTUSER.DAT'];logs=[Evidence('NTUSER.DAT.'+suffix,streams['NTUSER.DAT.'+suffix]) for suffix in order if 'NTUSER.DAT.'+suffix in streams]
    r=recover_hive(hive,logs,hive_name='NTUSER.DAT');assert all(not s.closed and hashlib.sha256(s.getvalue()).hexdigest()==hashes[k] for k,s in streams.items());return r

def observation(r):return {'status':r.status.value,'published':r.recovered is not None,'selected':[x.sequence for x in r.report.selected_chain],'paired':[x.paired for x in r.report.logs],'pairing_notes':[x.pairing_notes for x in r.report.logs],'log_warnings':[x.warnings for x in r.report.logs],'structure_trustworthy':None if r.report.structure is None else r.report.structure.trustworthy}
def normal():
    a=run(order=('LOG1','LOG2'));b=run();assert a.recovered_bytes==b.recovered_bytes and a.recovered.hive.root().value('RootV').data==b'GEN14...........';return observation(b)
def short1():
    r=run(chunk=1);assert r.status==RecoveryStatus.RECOVERED and r.recovered.hive.root().value('RootV').data==b'GEN14...........';return observation(r)
def short7():
    r=run(chunk=7);assert r.status==RecoveryStatus.RECOVERED;return observation(r)
def conflict():
    r=run('conflict');assert r.status==RecoveryStatus.FAILED and r.recovered is None;return observation(r)
def missing():
    r=run('missing');assert r.status==RecoveryStatus.FAILED and r.recovered is None;return observation(r)
def old():
    r=run('old');assert r.status==RecoveryStatus.UNSUPPORTED and r.recovered is None;return observation(r)
def cycle():
    r=run('cycle');assert r.recovered is not None and r.report.structure.trustworthy is False and r.report.structure.cycles;return observation(r)
def trailing():
    r=run('trailing');assert r.status==RecoveryStatus.RECOVERED_PARTIAL and r.recovered is not None;return observation(r)
def truncated():
    r=run('truncated');assert r.status==RecoveryStatus.RECOVERED_PARTIAL and all(x.sequence==12 for x in r.report.selected_chain);return observation(r)
def foreign_name():
    def mutate(files):
        for name in list(files):
            if '.LOG' in name:
                b=bytearray(files[name]);b[48:112]='SOFTWARE'.encode('utf-16-le').ljust(64,b'\x00');struct.pack_into('<I',b,508,checksum(b));files[name]=bytes(b)
        return files
    r=run(mutator=mutate);o=observation(r);assert r.recovered is None or all(x.paired is False for x in r.report.logs),o;return o
def invalid_header_checksum():
    def mutate(files):
        for name in list(files):
            if '.LOG' in name:
                b=bytearray(files[name]);b[508]^=0x80;files[name]=bytes(b)
        return files
    r=run(mutator=mutate);o=observation(r);assert r.status!=RecoveryStatus.RECOVERED,o;return o
CASES=[normal,short1,short7,conflict,missing,old,cycle,trailing,truncated,foreign_name,invalid_header_checksum]
if __name__=='__main__':
    result=[]
    for fn in CASES:
        try:o=fn();result.append({'case':fn.__name__,'status':'PASS','observed':o})
        except Exception as e:result.append({'case':fn.__name__,'status':'FAIL','exception':type(e).__name__,'detail':str(e)})
    print(json.dumps({'source':'Submitted synthetic binary fixtures; independent mutation and contract assertions, source untouched','results':result,'passed':sum(x['status']=='PASS' for x in result),'failed':sum(x['status']=='FAIL' for x in result)},indent=2))
    raise SystemExit(int(any(x['status']=='FAIL' for x in result)))