"""Normal Mac Apple events addressed to an existing PID. Never request interaction."""
import ctypes as C
import json
import sys

LIB=C.CDLL('/System/Library/Frameworks/CoreServices.framework/CoreServices')
class Desc(C.Structure):
    _fields_=[('descriptorType',C.c_uint32),('dataHandle',C.c_void_p)]
DP=C.POINTER(Desc);U=C.c_uint32;S=C.c_long
for name,args,ret in [
 ('AECreateDesc',[U,C.c_void_p,S,DP],C.c_int16),
 ('AECreateList',[C.c_void_p,S,C.c_ubyte,DP],C.c_int16),
 ('AEPutParamDesc',[DP,U,DP],C.c_int16),
 ('AECoerceDesc',[DP,U,DP],C.c_int16),
 ('AECreateAppleEvent',[U,U,DP,C.c_int16,C.c_int32,DP],C.c_int16),
 ('AESendMessage',[DP,DP,C.c_int32,C.c_int32],C.c_int32),
 ('AEGetParamPtr',[DP,U,U,C.POINTER(U),C.c_void_p,S,C.POINTER(S)],C.c_int16),
 ('AEGetParamDesc',[DP,U,U,DP],C.c_int16),
 ('AEDisposeDesc',[DP],C.c_int16)]:
    fn=getattr(LIB,name);fn.argtypes=args;fn.restype=ret

def cc(text):return int.from_bytes(text.encode('ascii'),'big')
class AppleEvents:
    def __init__(self,pid):
        self.owned=[]
        self.target=self.desc('kpid',int(pid).to_bytes(4,sys.byteorder,signed=True))
    def close(self):
        for item in reversed(self.owned):LIB.AEDisposeDesc(C.byref(item))
        self.owned=[]
    def new(self):
        item=Desc();self.owned.append(item);return item
    def checked(self,status):
        if status:raise RuntimeError('APPLE_EVENT_STATUS_'+str(status))
    def desc(self,kind,payload=b''):
        item=self.new();buffer=C.create_string_buffer(payload)
        self.checked(LIB.AECreateDesc(cc(kind),buffer,len(payload),C.byref(item)));return item
    def type(self,value):return self.desc('type',cc(value).to_bytes(4,sys.byteorder))
    def enum(self,value):return self.desc('enum',cc(value).to_bytes(4,sys.byteorder))
    def text(self,value):return self.desc('utf8',value.encode())
    def integer(self,value):return self.desc('long',int(value).to_bytes(4,sys.byteorder,signed=True))
    def record(self,values,kind='reco'):
        item=self.new();self.checked(LIB.AECreateList(None,0,1,C.byref(item)))
        for key,value in values.items():self.checked(LIB.AEPutParamDesc(C.byref(item),cc(key),C.byref(value)))
        if kind!='reco':
            output=self.new();self.checked(LIB.AECoerceDesc(C.byref(item),cc(kind),C.byref(output)));return output
        return item
    def obj(self,want,form,data,container=None):
        return self.record({'want':self.type(want),'form':self.enum(form),'seld':data,'from':container if container is not None else self.desc('null')},'obj ')
    def prop(self,name,container=None):return self.obj('prop','prop',self.type(name),container)
    def value(self,record,key,kind):
        actual=U();size=S();buffer=C.create_string_buffer(16384)
        status=LIB.AEGetParamPtr(C.byref(record),cc(key),cc(kind),C.byref(actual),buffer,len(buffer),C.byref(size))
        if status==-1701:return None
        self.checked(status)
        raw=buffer.raw[:size.value]
        if kind=='utf8':return raw.decode('utf8')
        if kind=='long':return int.from_bytes(raw,sys.byteorder,signed=True)
        return raw
    def send(self,event_class,event_id,params):
        event=self.new()
        self.checked(LIB.AECreateAppleEvent(cc(event_class),cc(event_id),C.byref(self.target),-1,0,C.byref(event)))
        for key,value in params.items():self.checked(LIB.AEPutParamDesc(C.byref(event),cc(key),C.byref(value)))
        reply=self.new()
        # Wait for reply, never interact, don't record. TCC/Automation policy is unchanged.
        self.checked(LIB.AESendMessage(C.byref(event),C.byref(reply),0x1013,300))
        error=self.value(reply,'errn','long')
        if error:raise RuntimeError('APPLE_EVENT_REPLY_'+str(error))
        return reply
    def get(self,obj,kind='utf8'):
        return self.value(self.send('core','getd',{'----':obj}),'----',kind)
    def returned_spec(self,reply):
        item=self.new();self.checked(LIB.AEGetParamDesc(C.byref(reply),cc('----'),cc('obj '),C.byref(item)));return item

if __name__=='__main__':
    events=AppleEvents(int(sys.argv[1]))
    try:
        version=events.get(events.prop('vers'))
        print(json.dumps(dict(state='AVAILABLE',version=version)))
    except Exception as error:print(json.dumps(dict(state='UNAVAILABLE',reason=str(error))))
    finally:events.close()
