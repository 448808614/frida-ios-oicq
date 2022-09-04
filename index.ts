import {FCCommon} from "./utils/FCCommon";
import {FCiOS} from "./utils/FCiOS";
import {Anti} from "./utils/android/Anti";
import anti_debug = Anti.anti_debug;
import {DMLog} from "./utils/dmlog";
import arrayBuffer2Hex = FCCommon.arrayBuffer2Hex;

if (Java.available) {
    anti_debug()
}

if (ObjC.available) {
    // FCiOS.trace_NSLog()
    // FCiOS.trace_url()


    //QQPacketDispatchBlockCbService/GuildQQGProPacketService/WupTransportationProxy/ODQQSSOChannel
    ObjC.classes["QPacketDispatchService"].$ownMethods.forEach(function (name) {
        // console.log("name: [" + name + "]")
    })

    hook_packet()
    //hook_ecdh()
    //hook_tlv()

    const targets = FCiOS.findAllByPattern('**[** *WupBufafer*]');
    targets.forEach(function (target: any) {
        // DMLog.i('FindClass', 'target.name: ' + target.name + ', target.address: ' + target.address);
    });
}

function hook_packet() {
    // - decodeRspData:request:error:
    // - encodeReqBizData:outError:


    // [- sendWupBuffer:cmd:seq:immediately:timeOut:]
    //  [- sendWupBuffer:cmd:seq:immediately:]
    // [- sendWupBuffer:cmd:seq:immediately:timeOut:answerFlag:]
    //  [- sendWupBufferBase:cmd:seq:resendSeq:immediately:timeOut:answerFlag:isControl:]

    // [- ]
    // [- sendWupBuffer:cmd:seq:resendSeq:immediately:isControl:answeiFlag:timeOut:isNotCombine:traceInfo:withDelegate:]

    //  [- sendWupBuffer:cmd:seq:immediately:timeOut:answerFlag:isControl:andIsCombine:]
//sendWupBuffer:cmd:seq:resendSeq:immediately:isControl:answeiFlag:timeOut:isNotCombine:traceInfo:transInfo:withDelegate:
    Interceptor.attach(ObjC.classes["QPacketDispatchService"]["- sendWupBufferBase:cmd:seq:resendSeq:immediately:timeOut:answerFlag:isControl:traceInfo:transInfo:accountUin:"].implementation, {
        onEnter:args => {
            console.log("===============<A>")

            let cmd = new ObjC.Object(args[3]).toString()
            let dataPtr = new NativePointer(args[2])
            let length = new Buffer(dataPtr.readByteArray(4)!!)
                .readUInt32BE(0)
            let wupBuffer = dataPtr.readByteArray(length + 4)!!.slice(4)
            let uin = int64(new ObjC.Object(args[11]).toString())
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

            console.log("Tlv", "0x" + ver.toString(16), arrayBuffer2Hex(value))
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
            console.log("WtloginPlatformInfoV2", arrayBuffer2Hex(share_key))
            console.log("WtloginPlatformInfoV2", arrayBuffer2Hex(public_key))
        }
    })
}
