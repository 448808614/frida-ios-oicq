import {FCCommon} from "./utils/FCCommon";
import {FCiOS} from "./utils/FCiOS";
import {Anti} from "./utils/android/Anti";
import anti_debug = Anti.anti_debug;
import {DMLog} from "./utils/dmlog";

if (Java.available) {
    anti_debug()
}

if (ObjC.available) {
    // FCiOS.trace_NSLog()
    // FCiOS.trace_url()


    //
    ObjC.classes["QQECNetwork"].$ownMethods.forEach(function (name) {
        // console.log("name: [" + name + "]")
    })

    // hook_packet()
    //hook_ecdh()
    //hook_tlv()

    const targets = FCiOS.findAllByPattern('**[*Codec* *Cmd*]');
    targets.forEach(function (target: any) {
        DMLog.i('FindClass', 'target.name: ' + target.name + ', target.address: ' + target.address);
    });
}

function hook_packet() {
    // - decodeRspData:request:error:
    // - encodeReqBizData:outError:

    Interceptor.attach(ObjC.classes["QQECNetwork"]["- requestWithCmd:reqParams:successBlock:errorBlock:"].implementation, {
        onEnter:args => {
            console.log("===============<J>")
        }
    })

    Interceptor.attach(ObjC.classes["QQECNetwork"]["- encodeReqParams:params:"].implementation, {
        onEnter:args => {
            console.log("===============<K>")
        }
    })

    // rb: TXCCodecUtils/QQExpandSSOStreamCodec/QQProtobufJSONCodec/SEJceCodec
    Interceptor.attach(ObjC.classes["QQNetworkSSOCodecImp"]["- encodeReq:error:"].implementation, {
        onEnter:args => {
            console.log("===================<B>")
            //console.log(args[2])
            //console.log(args[3])
            //console.log(args[4])
            //console.log(args[5])
        }
    })
    Interceptor.attach(ObjC.classes["QQSSOBaseCodec"]["- encodeReq:error:"].implementation, {
        onLeave:retval => {
            let r = new ObjC.Object(retval)
            console.log(r)
        }
    })

}

function hook_tlv() {
    Interceptor.attach(ObjC.classes["WloginTlv_Buff"]["- encode:"].implementation, {
        onEnter: args => {
            let buff = new ObjC.Object(args[0])
            let ver: number = buff.$ivars["wTlvT"]
            let value_ptr = buff.$ivars["acSigBuff"]
            let value = new NativePointer(value_ptr.bytes())
                .readByteArray(value_ptr.length())!!

            console.log("Tlv", "0x" + ver.toString(16), buf2hex(value))
        },
    })
}

function hook_ecdh() {
    console.log("Start hooking ecdh...")
    let WtloginPlatformInfo: ObjC.Object

    Interceptor.attach(ObjC.classes["WtloginPlatformInfo"]["- setECDHShareKey:andPubKey:andPubKeyLen:wKeyVer:"].implementation, {
        onEnter: function (args) {
            WtloginPlatformInfo = new ObjC.Object(args[0])

            let share_key = new NativePointer(args[2])
                .readByteArray(16)!!
            let public_key = new NativePointer(args[3])
                .readByteArray(args[4].toInt32())!!

            console.log("Hook ecdh successful!!!")
            console.log("WtloginPlatformInfoV2", buf2hex(share_key))
            console.log("WtloginPlatformInfoV2", buf2hex(public_key))
        }
    })
}

function buf2hex(buffer: ArrayBuffer): string { // buffer is an ArrayBuffer
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}