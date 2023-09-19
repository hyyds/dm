import json
import re
import logging
import os
import frida
import flask
from urllib.parse import quote

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

os.environ['FLASK_ENV']="development"

server = flask.Flask(__name__)


def on_message(message, data):
    if message["type"] == "send":
        print("{0}".format(message["payload"]))
    else:
        print(message)

# hook代码
jscode = """
rpc.exports = {
      spdy() {
        Java.perform(function () {
            var SwitchConfig = Java.use('mtopsdk.mtop.global.SwitchConfig');
            var config = SwitchConfig.getInstance();
            config.setGlobalSpdySslSwitchOpen(false);
            config.setGlobalSpdySwitchOpen(false);
        })
      },
      sign(api, apiVersion, body, isWua) {
            return new Promise((resolve) => {
                Java.perform(function () {
                    // 引入Java中的类
                    const MtopRequest = Java.use('mtopsdk.mtop.domain.MtopRequest')
                    const MtopBusiness = Java.use('com.taobao.tao.remotebusiness.MtopBusiness')
                    const MethodEnum = Java.use('mtopsdk.mtop.domain.MethodEnum')
                    const System = Java.use('java.lang.System')
                    const ApiID = Java.use('mtopsdk.mtop.common.ApiID')
                    const MtopStatistics = Java.use('mtopsdk.mtop.util.MtopStatistics')
                    const InnerProtocolParamBuilderImpl = Java.use(
                        'mtopsdk.mtop.protocol.builder.impl.InnerProtocolParamBuilderImpl'
                    )
                    const MtopUtils = Java.use('mtopsdk.common.util.MtopUtils')
                    const HashMap2Str = (params_hm) => {
                        const HashMap = Java.use('java.util.HashMap')
                        const args_map = Java.cast(params_hm, HashMap)
                        return args_map.toString()
                    }

                    // create MtopRequest
                    const myMtopRequest = MtopRequest.$new()
                    myMtopRequest.setApiName(api)
                    myMtopRequest.setData(body)
                    myMtopRequest.setNeedEcode(true)
                    myMtopRequest.setNeedSession(true)
                    myMtopRequest.setVersion(apiVersion)

                    // create MtopBusiness
                    const myMtopBusiness = MtopBusiness.build(myMtopRequest)
                    if (isWua === 'true') myMtopBusiness.useWua()
                    myMtopBusiness.reqMethod(MethodEnum.POST.value)
                    myMtopBusiness.setCustomDomain('mtop.damai.cn')
                    myMtopBusiness.setBizId(24)
                    myMtopBusiness.setErrorNotifyAfterCache(true)
                    myMtopBusiness.reqStartTime = System.currentTimeMillis()
                    myMtopBusiness.isCancelled = false
                    myMtopBusiness.isCached = false
                    myMtopBusiness.clazz = null
                    myMtopBusiness.requestType = 0
                    myMtopBusiness.requestContext = null
                    myMtopBusiness.mtopCommitStatData(false)
                    myMtopBusiness.sendStartTime = System.currentTimeMillis()

                    const createListenerProxy = myMtopBusiness.$super.createListenerProxy(myMtopBusiness.$super.listener.value)
                    const createMtopContext = myMtopBusiness.createMtopContext(createListenerProxy)
                    createMtopContext.stats.value = MtopStatistics.$new(null, null)
                    myMtopBusiness.$super.mtopContext.value = createMtopContext
                    createMtopContext.apiId.value = ApiID.$new(null, createMtopContext)

                    const myMtopContext = createMtopContext
                    myMtopContext.mtopRequest.value = myMtopRequest
                    const myInnerProtocolParamBuilderImpl = InnerProtocolParamBuilderImpl.$new()
                    const res = myInnerProtocolParamBuilderImpl.buildParams(myMtopContext)

                    const mtop = myMtopContext.mtopInstance.value
                    const utdid = mtop.getMtopConfig().utdid.value
                    const aa = MtopUtils.createIntSeqNo() % 10000
                    const xctraceid = utdid + System.currentTimeMillis() + '0' + aa + '1' + mtop.getMtopConfig().processId.value
                    const sign = HashMap2Str(res).replace('x-c-traceid=null', `x-c-traceid=${xctraceid}`)
                    resolve(sign)
                })
            })
        }
};  """


def start_hook():
    # 开始hook
    device = frida.get_usb_device()
    process = device.attach("大麦")
    script = process.create_script(jscode)
    script.on("message", on_message)
    script.load()
    script.exports_sync.spdy()
    return script

@server.route('/getSign', methods=['GET'])
def sign():
    try:
        api = flask.request.args.get('api')
        apiVersion = flask.request.args.get('apiVersion')
        body = flask.request.args.get('body')
        isWua = flask.request.args.get('isWua')
        result = script.exports_sync.sign(api, apiVersion, body, isWua)
        return { "code": 1, "data": result, "message": "sucess" }
    except Exception as e:
        print(e)
        return 'sign error'

script = start_hook()

if __name__ == '__main__':
    server.run(host='0.0.0.0', port=8888)


