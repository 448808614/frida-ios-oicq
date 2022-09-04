import {FCCommon} from "./utils/FCCommon";
import {FCiOS} from "./utils/FCiOS";
import {Anti} from "./utils/android/Anti";
import anti_debug = Anti.anti_debug;
import {DMLog} from "./utils/dmlog";
import arrayBuffer2Hex = FCCommon.arrayBuffer2Hex;
import Object = ObjC.Object;

if (Java.available) {
    anti_debug()
}

if (ObjC.available) {
    // FCiOS.trace_NSLog()
    // FCiOS.trace_url()


    //QQPacketDispatchBlockCbService/GuildQQGProPacketService/WupTransportationProxy/ODQQSSOChannel
    ObjC.classes["QPacketDispatchService"].$ownMethods.forEach(function (name) {
        console.log("name: [" + name + "]")
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
    let uin: Int64

    let QPacketDispatchService = ObjC.classes["QPacketDispatchService"]
    Interceptor.attach(QPacketDispatchService["- onMSFRecvDataFromBackend:buf:bufLen:seq:channelSource:"].implementation, {
        onEnter:args => {
            console.log("===============<FromService>")
            let seq = args[5].toInt32()
            let cmd: string
            {
                let buffer = new Buffer(
                    args[2].readByteArray(64)!!
                )

                for (let i = 0; i < 64; i++) {
                    if(buffer.readInt8(i) == 0) {
                        buffer = buffer.slice(0, i)
                        break
                    }
                }

                cmd = buffer.toString()
            }
            let dataPtr = new NativePointer(args[3])
            let wupBuffer = dataPtr.readByteArray(args[4].toUInt32() + 4)!!.slice(4)

            console.log("[CMD]", cmd)
            console.log("[UIN]", uin)
            console.log("[SEQ]", seq)
            // console.log("[BUFFER]", arrayBuffer2Hex(wupBuffer))
        }
    })
    Interceptor.attach(QPacketDispatchService["- sendWupBufferBase:cmd:seq:resendSeq:immediately:timeOut:answerFlag:isControl:traceInfo:transInfo:accountUin:"].implementation, {
        onEnter:args => {
            let cmd = new ObjC.Object(args[3]).toString()
            let dataPtr = new NativePointer(args[2])
            let length = new Buffer(dataPtr.readByteArray(4)!!)
                .readUInt32BE(0)
            let wupBuffer = dataPtr.readByteArray(length + 4)!!.slice(4)
            uin = int64(new ObjC.Object(args[11]).toString())
            let seq = new ObjC.Object(args[0])["- getSeq"]()

            console.log("===============<ToService>")
            console.log("[CMD]", cmd)
            console.log("[UIN]", uin)
            console.log("[SEQ]", seq)
            // console.log("[BUFFER]", arrayBuffer2Hex(wupBuffer))

            // 6/9/10 bool
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
