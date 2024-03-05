<?php
$config = parse_ini_file("./config.ini");
if (empty($config)) {
    die("配置文件错误");
}

/*
 * 校验
 */
$portStr = $config['client_port'] ?? '';
if (empty($portStr)) {
    die("端口错误");
}

$msgContent = $config['msg']??'';
if (empty($msgContent)) {
    die("请配置要发送的内容");
}

$mobileStr = $config['mobile']??'';
if (empty($msgContent)) {
    die("请配置起始发送号码");
}



use Swoole\Coroutine;
use Swoole\Coroutine\Client;
use Swoole\Coroutine\Channel;

class Smpp3Protocol
{
    //操作
    const GENERIC_NACK = 0x00000000;
    const BIND_RECEIVER = 0x00000001;
    const BIND_RECEIVER_RESP = 0x80000001;
    const BIND_TRANSMITTER = 0x00000002;
    const BIND_TRANSMITTER_RESP = 0x80000002;
    const QUERY_SM = 0x00000003;
    const QUERY_SM_RESP = 0x80000003;
    const SUBMIT_SM = 0x00000004;
    const SUBMIT_SM_RESP = 0x80000004;
    const DELIVER_SM = 0x00000005;
    const DELIVER_SM_RESP = 0x80000005;
    const UNBIND = 0x00000006;
    const UNBIND_RESP = 0x80000006;
    const REPLACE_SM = 0x00000007;
    const REPLACE_SM_RESP = 0x80000007;
    const CANCEL_SM = 0x00000008;
    const CANCEL_SM_RESP = 0x00000008;
    const BIND_TRANSCEIVER = 0x00000009;
    const BIND_TRANSCEIVER_RESP = 0x80000009;
    const OUTBIND = 0x0000000B;
    const ENQUIRE_LINK = 0x00000015;
    const ENQUIRE_LINK_RESP = 0x80000015;
    const SUBMIT_MULTI = 0x00000021;
    const SUBMIT_MULTI_RESP = 0x80000021;
    const ALERT_NOTIFICATION = 0x000000101;
    const DATA_SM = 0x000000103;
    const DATA_SM_RESP = 0x800000103;
    //deliver_sm中esm_class为4则代表是report
    const ESM_CLASS_DELIVERY_REPORT = 0x4;
    const ESM_CLASS_DELIVERY = 0x8;
    const ESM_CLASS_UDHI = 0x40;
    //错误
    const ESME_ROK = 0x00000000;                                                                             //无错误
    const ESME_RINVCMDID = 0x00000003;                                                                       //无效的命令ID
    const ESME_RINVSRCADR = 0x0000000A;                                                                      //原地址无效
    const ESME_RINVPASWD = 0x0000000E;                                                                       //密码错误
    const ESME_RINVSYSID = 0x0000000F;                                                                       //无效的sp
    const ESME_RTHROTTLED = 0x00000058;                                                                    //超速
    const ESME_PREPARE_START = 0x00000501;                                                                   //服务器未初始化好
    const ESME_SERVER_RESOURCE_ERR = 0x00000502;                                                             //服务器资源耗尽
    const ESME_EXCEED_CO_NUM = 0x00000503;                                                                   //携程数量过多
    const ESME_ERR_CONNECT_NUM_OUT = 0x00000504;                                                             //重试连接数超限
    const ESME_EXCEED_CON_NUM = 0x00000505;                                                                  //连接数超限
    const ESME_PRODUCT_LOCKED = 0x00000506;                                                                  //产品被锁定
    const ESME_PRODUCT_TYPE_LOCKED = 0x00000507;                                                             //产品类型被锁定
    const ESME_INS_BALANCE = 0x00000510;                                                                     //余额不足
    const ESME_ERR_LONG = 0x00000511;                                                                        //长信参数错误
    const ESME_PRODUCT_TYPE_ERR = 0x00000512;                                                                //长信参数错误
    const TAG_SAR_MSG_REF_NUM = 0x020C;
    const TAG_SAR_TOTAL_SEGMENTS = 0x020E;
    const TAG_SAR_SEGMENT_SEQNUM = 0x020F;
    const TAG_MESSAGE_PAYLOAD = 0x0424;
    const DATA_CODING_DEFAULT = 0;
    const DATA_CODING_UCS2 = 8;
    // UCS-2BE (Big Endian)
    public static $headerUnpackRule = 'Ncommand_length/Ncommand_id/Ncommand_status/Nsequence_number';        //头部解析规则
    public static $headerPackRule = 'NNNN';                                                                  //头部解析规则
    private static $sequenceId = 0;

    public static function generateProSequenceId()
    {
        return ++self::$sequenceId;
    }

    /**
     * packBind
     * @param $commandId
     * @param $account
     * @param $pwd
     * @param $systemType
     * @param $interfaceVersion
     * @param $addr_ton
     * @param $addr_npi
     * @param $address_range
     * @return string
     */
    protected static function packBind($commandId, $account, $pwd, $systemType, $interfaceVersion, $addr_ton, $addr_npi, $address_range)
    {
        //生成响应体
        $respBodyBinary = pack(
            'a'.(strlen($account) + 1).
            'a'.(strlen($pwd) + 1).
            'a'.(strlen($systemType) + 1).
            'CCC'.
            'a'.(strlen($address_range) + 1),
            $account,
            $pwd,
            $systemType,
            $interfaceVersion,
            $addr_ton,
            $addr_npi,
            $address_range
        );

        //生成响应头
        $respHeaderBinary = pack(self::$headerPackRule, strlen($respBodyBinary) + 16, $commandId, null, self::generateProSequenceId());

        return $respHeaderBinary.$respBodyBinary;
    }

    /**
     * packBindResp
     * @param $commandId
     * @param $commandStatus
     * @param $sequenceNum
     * @param $systemId
     * @return string
     */
    public static function packBindResp($commandId, $commandStatus, $sequenceNum, $systemId)
    {
        if ($systemId) {
            $respBodyBinary = pack('a'.(strlen($systemId) + 1), $systemId);
        } else {
            $respBodyBinary = '';
        }

        $respHeaderBinary = pack(self::$headerPackRule, strlen($respBodyBinary) + 16, $commandId, $commandStatus, $sequenceNum);

        return $respHeaderBinary.$respBodyBinary;
    }

    /**
     * packBindTransceiver
     * @param $account
     * @param $pwd
     * @param $systemType
     * @param $interfaceVersion
     * @param $addr_ton
     * @param $addr_npi
     * @param $address_range
     * @return string
     */
    public static function packBindTransceiver($account, $pwd, $systemType, $interfaceVersion, $addr_ton, $addr_npi, $address_range)
    {
        return self::packBind(self::BIND_TRANSCEIVER, ...func_get_args());
    }

    /**
     * packBindTransceiverResp
     * @param $commandStatus
     * @param $sequenceNum
     * @param  null  $systemId
     * @return string
     */
    public static function packBindTransceiverResp($commandStatus, $sequenceNum, $systemId = null)
    {
        return self::packBindResp(self::BIND_TRANSCEIVER_RESP, $commandStatus, $sequenceNum, $systemId);
    }

    /**
     * packBindTransmitter
     * @param $account
     * @param $pwd
     * @param $systemType
     * @param $interfaceVersion
     * @param $addr_ton
     * @param $addr_npi
     * @param $address_range
     * @return string
     */
    public static function packBindTransmitter($account, $pwd, $systemType, $interfaceVersion, $addr_ton, $addr_npi, $address_range)
    {
        return self::packBind(self::BIND_TRANSMITTER, ...func_get_args());
    }

    /**
     * packBindTransmitterResp
     * @param $commandStatus
     * @param $sequenceNum
     * @param  null  $systemId
     * @return string
     */
    public static function packBindTransmitterResp($commandStatus, $sequenceNum, $systemId = null)
    {
        return self::packBindResp(self::BIND_TRANSMITTER_RESP, $commandStatus, $sequenceNum, $systemId);
    }

    /**
     * packBindReceiver
     * @param $account
     * @param $pwd
     * @param $systemType
     * @param $interfaceVersion
     * @param $addr_ton
     * @param $addr_npi
     * @param $address_range
     * @return string
     */
    public static function packBindReceiver($account, $pwd, $systemType, $interfaceVersion, $addr_ton, $addr_npi, $address_range)
    {
        return self::packBind(self::BIND_RECEIVER, ...func_get_args());
    }

    /**
     * packBindReceiverResp
     * @param $commandStatus
     * @param $sequenceNum
     * @param  null  $systemId
     * @return string
     */
    public static function packBindReceiverResp($commandStatus, $sequenceNum, $systemId = null)
    {
        return self::packBindResp(self::BIND_RECEIVER_RESP, $commandStatus, $sequenceNum, $systemId);
    }

    /**
     * packUnbind
     * @return string
     */
    public static function packUnbind()
    {
        return pack(self::$headerPackRule, 16, self::UNBIND, null, self::generateProSequenceId());
    }

    /**
     * packUnbindResp
     * @param $sequenceNum
     * @param  null  $commandStatus
     * @return string
     */
    public static function packUnbindResp($sequenceNum, $commandStatus = null)
    {
        return pack(self::$headerPackRule, 16, self::UNBIND_RESP, $commandStatus, $sequenceNum);
    }

    /**
     * packSubmitAndDeliver
     * @param $sourceAddr
     * @param $destinationAddr
     * @param $shortMessage
     * @param $esmClass
     * @param $commandId
     * @param $sequenceNum
     * @param $dataEncoding
     * @return string
     */
    protected static function packSubmitAndDeliver($sourceAddr, $destinationAddr, $shortMessage, $esmClass, $commandId, $sequenceNum, $dataEncoding)
    {
        $sourceAddrLen = strlen($sourceAddr);

        if ($sourceAddrLen > 21) {
            $sourceAddrLen = 21;

            $sourceAddr = substr($sourceAddr, 0, 21);
        }

        $destinationAddrLen = strlen($destinationAddr);

        if ($destinationAddrLen > 21) {
            $destinationAddrLen = 21;

            $destinationAddr = substr($destinationAddr, 0, 21);
        }

        $smsLen = strlen($shortMessage);

        if ($commandId === self::DELIVER_SM && $smsLen > 254) {
            //如果是deliver超长不支持分片，需要走payload
            $payload    = $shortMessage;
            $payloadLen = $smsLen;

            $shortMessage = '';
            $smsLen       = 0;
        }

        $respBodyBinary = pack(
            'aCC'.
            'a'.($sourceAddrLen + 1).
            'CC'.
            'a'.($destinationAddrLen + 1).
            'CCCaaCCCCC'.
            'a'.$smsLen
            ,
            null,          //service_type
            5,             //source_addr_ton
            0,                   //source_addr_npi
            $sourceAddr,         //source_addr
            1,                   //dest_addr_ton
            1,                   //dest_addr_npi
            $destinationAddr,    //destination_addr
            $esmClass,           //esm_class 长信如果需要拆分发送则需要设置此字段 合并发送则默认无需设置
            0,                   //protocol_id
            3,                   //priority_flag
            null,                //schedule_delivery_time
            null,                //validity_period
            1,                   //registered_delivery
            0,                   //replace_if_present_flag
            $dataEncoding,       //data_coding
            0,                   //sm_default_msg_id
            $smsLen,             //sm_length
            $shortMessage//sm_length
        );

        if (isset($payload)) {
            $respBodyBinary .= pack('nna*', 0x0424, $payloadLen, $payload);
        }

        //生成响应头
        $respHeaderBinary = pack(self::$headerPackRule, strlen($respBodyBinary) + 16, $commandId, null, $sequenceNum);

        return $respHeaderBinary.$respBodyBinary;
    }

    /**
     * packSubmitSm
     * @param $sourceAddr
     * @param $destinationAddr
     * @param $shortMessage
     * @param $sequenceNum
     * @param $esmClass
     * @return string
     */
    public static function packSubmitSm($sourceAddr, $destinationAddr, $shortMessage, $sequenceNum, $esmClass, $dataEncoding)
    {
        return self::packSubmitAndDeliver($sourceAddr, $destinationAddr, $shortMessage, $esmClass, self::SUBMIT_SM, $sequenceNum, $dataEncoding);
    }

    /**
     * packSubmitSmResp
     * @param $commandStatus
     * @param $sequenceNum
     * @param  null  $msgId
     * @return string
     */
    public static function packSubmitSmResp($commandStatus, $sequenceNum, $msgId = null)
    {
        if ($msgId) {
            $respBodyBinary = pack('a'.(strlen($msgId) + 1), $msgId);
        } else {
            $respBodyBinary = '';
        }

        $respHeaderBinary = pack(self::$headerPackRule, strlen($respBodyBinary) + 16, self::SUBMIT_SM_RESP, $commandStatus, $sequenceNum);

        return $respHeaderBinary.$respBodyBinary;
    }

    /**
     * packDeliverSm
     * @param $esmClass
     * @param $sourceAddr
     * @param $destinationAddr
     * @param $shortMessage
     * @return string
     */
    public static function packDeliverSm($esmClass, $sourceAddr, $destinationAddr, $shortMessage)
    {
        if ($esmClass === self::ESM_CLASS_DELIVERY_REPORT) {
            //report
            $date = date('ymdHi');

            $shortMessage = implode(' ', [
                'id:'.$shortMessage['id'],
                'sub:'.'000',
                'dlvrd:'.'000',
                'submit date:'.$date,
                'done date:'.$date,
                'stat:'.$shortMessage['stat'],
                'err:'.'000',
                'text:'.$shortMessage['text'],
            ]);
        }

        return self::packSubmitAndDeliver($sourceAddr, $destinationAddr, $shortMessage, $esmClass, self::DELIVER_SM, self::generateProSequenceId(), self::DATA_CODING_UCS2);
    }

    /**
     * packDeliverSmResp
     * @param $sequenceNum
     * @return string
     */
    public static function packDeliverSmResp($sequenceNum)
    {
        $respBodyBinary = pack('a', null);

        //生成响应头
        $respHeaderBinary = pack(self::$headerPackRule, strlen($respBodyBinary) + 16, self::DELIVER_SM_RESP, self::ESME_ROK, $sequenceNum);

        return $respHeaderBinary.$respBodyBinary;
    }

    /**
     * packEnquireLink
     * @return string
     */
    public static function packEnquireLink()
    {
        return pack(self::$headerPackRule, 16, self::ENQUIRE_LINK, null, self::generateProSequenceId());
    }

    /**
     * packEnquireLinkResp
     * @param $sequenceNum
     * @return false|string
     */
    public static function packEnquireLinkResp($sequenceNum)
    {
        return pack(self::$headerPackRule, 16, self::ENQUIRE_LINK_RESP, null, $sequenceNum);
    }

    /**
     * packGenericNack
     * @param $commandStatus
     * @param $sequenceNum
     * @return false|string
     */
    public static function packGenericNack($commandStatus, $sequenceNum)
    {
        return pack(self::$headerPackRule, 16, self::GENERIC_NACK, $commandStatus, $sequenceNum);
    }

    /**
     * unpackHeader
     * @param $headerBinary
     * @return array
     */
    public static function unpackHeader($headerBinary)
    {
        return @unpack(self::$headerUnpackRule, $headerBinary) ?: [];
    }

    /**
     * unpackBind
     * @param $bodyBinary
     * @return array
     */
    public static function unpackBind($bodyBinary)
    {
        if (empty($bodyBinary)) {
            return [];
        }

        $binaryArr = explode(chr(0), $bodyBinary, 3);

        if (empty($binaryArr[0]) || empty($binaryArr[1])) {
            return [];
        }

        $bodyArr = unpack('a'.strlen($binaryArr[0]).'system_id/a'.strlen($binaryArr[1]).'password', $binaryArr[0].$binaryArr[1]);

        return $bodyArr ?: [];
    }

    /**
     * unpackBindResp
     * @param $bodyBinary
     * @return array
     */
    public static function unpackBindResp($bodyBinary)
    {
        if (empty($bodyBinary)) {
            return [];
        }

        $binaryArr = explode($bodyBinary, chr(0), 2);

        $bodyArr = @unpack('a'.strlen($binaryArr[0]).'system_id', $binaryArr[0]) ?: [];

        if (isset($binaryArr[1]) && $tagArr = @unpack('ntag/nlength/Cvalue', $binaryArr[1])) {
            $bodyArr['sc_interface_version'] = $tagArr['value'];
        }

        return $bodyArr;
    }

    /**
     * unpackSubmitAndDeliver
     * @param $bodyBinary
     * @return array
     */
    protected static function unpackSubmitAndDeliver($bodyBinary)
    {
        $serviceTypePos = strpos($bodyBinary, chr(0));

        $sourceAddrOffset = $serviceTypePos + 3;

        $sourceAddrPos = strpos($bodyBinary, chr(0), $sourceAddrOffset);

        $destinationAddrOffset = $sourceAddrPos + 3;

        $destinationAddrPos = strpos($bodyBinary, chr(0), $destinationAddrOffset);

        if ($serviceTypePos === false || $sourceAddrPos === false || $destinationAddrPos === false) {
            return [];
        }

        $scheduleDeliveryTimeOffset = $destinationAddrPos + 4;

        $scheduleDeliveryTimePos = strpos($bodyBinary, chr(0), $scheduleDeliveryTimeOffset);

        if ($scheduleDeliveryTimePos === $scheduleDeliveryTimeOffset) {
            //如果null的位置和偏移量相等，则代表是1位
            $scheduleDeliveryTimeLength = 1;

            $validityPeriodOffset = $scheduleDeliveryTimePos + 1;
        } else {
            //否则代表是17位
            $scheduleDeliveryTimeLength = 17;

            $validityPeriodOffset = $scheduleDeliveryTimePos + 18;
        }

        $validityPeriodPos = strpos($bodyBinary, chr(0), $validityPeriodOffset);

        if ($validityPeriodPos === $validityPeriodOffset) {
            $validityPeriodLength = 1;
        } else {
            $validityPeriodLength = 17;
        }

        $smLengthPos = $validityPeriodPos + 5;

        $serviceTypeLength = $serviceTypePos + 1;

        $sourceAddrLength = $sourceAddrPos - $serviceTypePos - 2;

        $destinationAddrLength = $destinationAddrPos - $sourceAddrPos - 2;

        $smLength = unpack('C', $bodyBinary[$smLengthPos]);

        if ($smLength === false) {
            return [];
        }

        $smLength = reset($smLength);

        $rules = [
            'a'.$serviceTypeLength.'service_type',
            'Csource_addr_ton',
            'Csource_addr_npi',
            'a'.$sourceAddrLength.'source_addr',
            'Cdest_addr_ton',
            'Cdest_addr_npi',
            'a'.$destinationAddrLength.'destination_addr',
            'Cesm_class',
            'Cprotocol_id',
            'Cpriority_flag',
            'a'.$scheduleDeliveryTimeLength.'schedule_delivery_time',
            'a'.$validityPeriodLength.'validity_period',
            'Cregistered_delivery',
            'Creplace_if_present_flag',
            'Cdata_coding',
            'Csm_default_msg_id',
            'Csm_length',
            'a'.$smLength.'short_message',
        ];

        $dataSm = @unpack(implode('/', $rules), $bodyBinary);

        if ($dataSm === false) {
            return [];
        }

        $tagsBinary = substr($bodyBinary, $smLengthPos + $smLength + 1);

        $tags = self::unpackTag($tagsBinary);

        if (isset($tags[self::TAG_MESSAGE_PAYLOAD])) {
            //长信转短信
            $dataSm['short_message'] = $tags[self::TAG_MESSAGE_PAYLOAD];
        } elseif (isset($tags[self::TAG_SAR_TOTAL_SEGMENTS])) {
            $dataSm['long_total']  = $tags[self::TAG_SAR_TOTAL_SEGMENTS];
            $dataSm['long_index']  = $tags[self::TAG_SAR_SEGMENT_SEQNUM];
            $dataSm['long_unique'] = $tags[self::TAG_SAR_MSG_REF_NUM];
        } elseif ($dataSm['esm_class'] & self::ESM_CLASS_UDHI) {
            $udhLen = substr($dataSm['short_message'], 0, 1);

            $dataSm['udh_len'] = unpack('cUdhLen', $udhLen)['UdhLen'];

            if ($dataSm['udh_len'] == 5) {
                $udh                     = substr($dataSm['short_message'], 3, 3);
                $dataSm['short_message'] = substr($dataSm['short_message'], 6);
                $dataSm                  += (array) unpack('clong_unique/clong_total/clong_index', $udh);
            } else {
                $udh                     = substr($dataSm['short_message'], 3, 4);
                $dataSm['short_message'] = substr($dataSm['short_message'], 7);
                $dataSm                  += (array) unpack('nlong_unique/clong_total/clong_index', $udh);
            }
        }

        foreach ($dataSm as $key => &$value) {
            if (is_array($value)) {
                foreach ($value as &$val) {
                    $val = is_string($val) ? trim($val) : $val;
                }
            } else {
                if ($key === 'short_message') {
                    continue;
                }

                $value = is_string($value) ? trim($value) : $value;
            }
        }

        return $dataSm;
    }

    /**
     * packLongSmsSlice
     * @param $message
     * @param $mark
     * @param $total
     * @param $index
     * @return string
     */
    public static function packLongSmsSlice($message, $mark, $total, $index)
    {
        $udh = pack('cccccc', 5, 0, 3, $mark, $total, $index);

        return $udh.$message;
    }

    /**
     * unpackTag
     * @param $binary
     * @return array
     */
    public static function unpackTag($binary)
    {
        if (empty($binary) || empty($lenBin = substr($binary, 2, 2))) {
            return [];
        }

        $len = unpack('n', $lenBin);

        if ($len === false) {
            return [];
        }

        $len = reset($len);

        $tag = unpack('nname/nlength/a'.$len.'value', $binary);

        if ($tag === false) {
            return [];
        }

        $tag = [$tag['name'] => $tag['value']];

        $surplusBinary = substr($binary, 4 + $len);

        $nextTag = self::unpackTag($surplusBinary);

        if (empty($nextTag)) {
            return $tag;
        } else {
            return ($tag + $nextTag) ?: [];
        }
    }

    /**
     * unpackSubmitSm
     * @param $bodyBinary
     * @return array
     */
    public static function unpackSubmitSm($bodyBinary)
    {
        return self::unpackSubmitAndDeliver($bodyBinary);
    }

    /**
     * unpackSubmitSmResp
     * @param $bodyBinary
     * @return array
     */
    public static function unpackSubmitSmResp($bodyBinary)
    {
        if ($bodyBinary) {
            $bodyArr = @unpack('a'.strlen($bodyBinary).'message_id', $bodyBinary);
        }

        $bodyArr = empty($bodyArr) ? [] : $bodyArr;

        foreach ($bodyArr as &$value) {
            $value = is_string($value) ? trim($value) : $value;
        }

        return $bodyArr;
    }

    /**
     * unpackDeliverSm
     * @param $bodyBinary
     * @return array
     */
    public static function unpackDeliverSm($bodyBinary)
    {
        if (empty($deliverArr = self::unpackSubmitAndDeliver($bodyBinary))) {
            return [];
        }

        if ($deliverArr['esm_class'] === self::ESM_CLASS_DELIVERY_REPORT) {
            //代表report 需要继续解包message
            $tmp = explode(' ', $deliverArr['short_message']);

            if ($tmp === false) {
                return [];
            }

            if (count($tmp) > 7) {
                //有的submit_data是以下划线有的以空格
                if (strpos($tmp[3], ':') === false) {
                    unset($tmp[3]);

                    $tmp[4] = 'submit_'.$tmp[4];
                }

                //兼容done date
                if (strpos($tmp[5], ':') === false) {
                    unset($tmp[5]);

                    $tmp[6] = 'done_'.$tmp[6];
                }
            }

            $deliverArr['short_message'] = [];

            foreach ($tmp as $value) {
                if (strpos($value, ':') === false) {
                    continue;
                }

                [$k, $v] = explode(':', $value, 2);

                $deliverArr['short_message'][$k] = $v;
            }
        }

        foreach ($deliverArr as $key => &$value) {
            if (is_array($value)) {
                foreach ($value as &$val) {
                    $val = is_string($val) ? trim($val) : $val;
                }
            } else {
                if ($key === 'short_message') {
                    continue;
                }

                $value = is_string($value) ? trim($value) : $value;
            }
        }

        return $deliverArr;
    }
}


trait EnquireLink
{
    protected $waitEnquireLinkResp = 0;//等待探活resp回来的数量
    protected $smscEnquireLikTime = 0;//对端主动探活时间

    /**
     * doEnquireLink
     */
    public function doEnquireLink()
    {
        while (true) {
            $enquireInterval = $this->smpp->getConfig('active_test_interval');

            //先休眠一个间隔时间
            while ($enquireInterval--) {
                Swoole\Coroutine::sleep(1);

                //如果我方主动关闭了则直接停止
                if (!$this->client->isConnected()) {
                    return;
                }
            }

            //如果对端探活在一个时间间隔内则继续休眠，并且重置我方探活
            if (time() - $this->smscEnquireLikTime < $this->smpp->getConfig('active_test_interval')) {
                $this->waitEnquireLinkResp = 0;

                continue;
            }


            //发送探活
            $this->send(Smpp3Protocol::packEnquireLink());

            if (++$this->waitEnquireLinkResp > $this->smpp->getConfig('active_test_num')) {
                //如果探活未回应次数大于配置则断开链接发送unbind
                $this->unbind();

                return;
            }
        }
    }

    /**
     * resetSmscEnquireLikTime
     */
    public function resetSmscEnquireLikTime()
    {
        $this->smscEnquireLikTime = time();
    }

    /**
     * handleEnquireLink
     * @param $sequenceNumber
     */
    public function handleEnquireLink($sequenceNumber)
    {
        //发送响应
        $this->send(Smpp3Protocol::packEnquireLinkResp($sequenceNumber));
    }

    /**
     * handleEnquireLinkResp
     */
    public function handleEnquireLinkResp()
    {
        //如果对端回了探活回应，则将等待数量-1，如果对端发来探活，我方会重置这个数，所以可能为负数需要重置
        if (--$this->waitEnquireLinkResp < 0) {
            $this->waitEnquireLinkResp = 0;
        }
    }
}

abstract class BaseTrans
{
    use EnquireLink;

    /** @var Client */
    protected $client;
    /** @var Smpp3Client */
    protected $smpp;
    /** @var Channel */
    protected $channel;

    abstract public function getBindPdu($account, $pwd);

    abstract public function unpackBindResp($pdu);

    abstract public function handlePdu($pdu);

    abstract public function close();

    public function __construct($smpp)
    {
        $this->client = new Client(SWOOLE_SOCK_TCP);

        $this->client->set([
            'open_length_check'     => true,
            'package_length_type'   => 'N',
            'package_length_offset' => 0,
            'package_body_offset'   => 0,
        ]);

        $this->smpp = $smpp;
    }

    /**
     * clientErr
     * @param  bool  $close
     * @return bool
     */
    protected function clientErr($close = true)
    {
        $this->smpp->syncClientErr($this->client->errCode, $this->client->errMsg);

        if ($close) {
            $this->client->close();
        }

        return false;
    }

    /**
     * customError
     * @param $errCode
     * @param $errMsg
     * @param  bool  $close
     * @return bool
     */
    protected function customError($errCode, $errMsg, $close = false)
    {
        $this->smpp->syncClientErr($errCode, $errMsg);

        if ($close) {
            $this->client->close();
        }

        return false;
    }

    /**
     * getSurplusTimeout
     * @param $timeout
     * @return bool|int
     */
    protected function getSurplusTimeout($timeout)
    {
        //如果过期时间是永不过期则直接返回
        if ($timeout <= 0) {
            return $timeout;
        }

        //求取剩余的超时时间
        $timeout = $timeout - time() + $this->smpp->getStartBindTime();

        return $timeout <= 0 ? false : $timeout;
    }

    /**
     * checkAndGetPdu
     * @param $timeout
     * @return bool|mixed
     */
    protected function checkAndGetPdu($timeout = -1)
    {
        if (!$this->client->isConnected()) {
            return $this->customError(8, 'the connection is broken');
        }

        if (($responsePdu = $this->client->recv($timeout)) === false) {
            //接收错误，如超时 同步客户端错误，不关闭链接

            if ($this->client->errCode === 104) {
                $this->customError(8, 'the connection is broken');
            } else {
                $this->clientErr(false);
            }

            return false;
        }

        if ($responsePdu === '') {
            //对端主动关闭了tcp链接 同步自定义错误，不关闭链接
            return $this->customError(8, 'the connection is broken');
        }

        if (strlen($responsePdu) < 16) {
            //login Response pdu长度异常 同步自定义错误，不关闭链接
            return $this->customError(93, 'Incorrect pdu command id');
        }

        return $responsePdu;
    }

    /**
     * doHook
     * @param $hook
     * @return mixed|null
     */
    protected function doHook($hook)
    {
        $hook && $hookRes = call_user_func($hook);

        return $hookRes ?? null;
    }

    /**
     * bind
     * @param $ip
     * @param $port
     * @param $account
     * @param $pwd
     * @param $timeout
     * @param  callable|null  $success
     * @param  callable|null  $fail
     * @return bool|array|mixed
     */
    public function bind($ip, $port, $account, $pwd, $timeout, ?callable $success = null, ?callable $fail = null)
    {
        if (($timeout = $this->getSurplusTimeout($timeout)) === false) {
            //如果超时了则返回超时错误，断开链接
            $this->customError(110, 'Connection timed');

            return self::doHook($fail) ?? false;
        }

        //进行tcp链接
        if (!$this->client->connect($ip, (int) $port, $timeout)) {
            //出错则断开链接
            $this->clientErr();

            return self::doHook($fail) ?? false;
        }

        //获取链接pdu
        $pdu = $this->getBindPdu($account, $pwd);

        //如果tcp链接就刚刚好超时了则返回超时错误 实际tcp链接上了
        if (($timeout = $this->getSurplusTimeout($timeout)) === false) {
            //断开链接
            $this->customError(110, 'Connection timed', true);

            return self::doHook($fail) ?? false;
        }

        //发送bind pdu
        if (!$this->client->send($pdu)) {
            //发送出错断开链接
            $this->clientErr();

            return self::doHook($fail) ?? false;
        }

        if (($responsePdu = $this->checkAndGetPdu($timeout)) === false) {
            //pdu接收错误 错误已经同步所以直接关闭链接就行
            $this->client->close();

            return self::doHook($fail) ?? false;
        }

        //解包
        if (($responseArr = $this->unpackBindResp($responsePdu)) === false) {
            //出错只有一种可能commandId不对，这是后断开链接
            $this->customError(8, 'Incorrect pdu command id', true);

            return self::doHook($fail) ?? false;
        }

        if ($responseArr['command_status'] !== Smpp3Protocol::ESME_ROK) {
            //如果链接失败，则关闭tcp链接
            $this->client->close();

            $hook = $fail;
        } else {
            $hook = $success;

            if (!isset($this->channel)) {
                $this->channel = new Channel(5000);

                Coroutine::create(function () {
                    while (true) {
                        if (!($this->channel instanceof Channel)) {
                            break;
                        }

                        $data = $this->channel->pop();

                        if (is_string($data)) {
                            $this->client->send($data);
                        } else {
                            $this->client->send($data[0]);

                            $this->client->close();

                            $this->channel->close();

                            $this->channel = null;
                        }
                    }
                });
            }
        }

        return self::doHook($hook) ?? $responseArr;
    }

    /**
     * unbind
     */
    public function unbind()
    {
        if ($this->client->errCode !== 8 && $this->client->errCode !== 110) {
            $pdu = Smpp3Protocol::packUnbind();

            $this->send([$pdu]);
        }
    }

    /**
     * handleUnbind
     * @param $sequenceNumber
     */
    public function handleUnbind($sequenceNumber)
    {
        $this->send([Smpp3Protocol::packUnbindResp($sequenceNumber)]);
    }

    /**
     * recv
     */
    public function recv()
    {
        while (true) {
            //recv出错
            if (($responsePdu = $this->checkAndGetPdu()) === false) {
                //如果错误是110或者8则断开链接其他情况不断开
                if ($this->smpp->errCode === 8 || $this->smpp->errCode === 110) {
                    //关闭tcp链接 如果是receiver或者transmitter则还需要关闭对应的接或者收器
                    $this->close();

                    //将false推入队列
                    $this->smpp->getChannel()->push($responsePdu);

                    break;
                }

                //其他情况比如长度不足则直接跳过
                Coroutine::sleep(1);

                continue;
            }

            $unpackData = $this->handlePdu($responsePdu);

            if ($unpackData) {
                $this->smpp->getChannel()->push($unpackData);
            }
        }
    }

    /**
     * send
     * @param $data
     */
    public function send($data)
    {
        if ($this->channel instanceof Channel) {
            $this->channel->push($data);
        }
    }
}

trait FlowRate
{
    protected $maxFlowRate;//最大流速
    protected $currentFlowRate = 0;//当前流速
    protected $currentSecond;//当前流速时间
    protected $currentHundredMillisecond;//当前流速时间的毫秒百位数
    protected $type = 1;//1一秒分成十分，2不分

    /**
     * setMaxFlowRate
     * @param $flowRate
     */
    public function setMaxFlowRate($flowRate, $type = 1)
    {
        $this->type = $type;

        if ($this->type === 1) {
            $this->maxFlowRate = (int) ($flowRate / 10);
        } else {
            $this->maxFlowRate = $flowRate;
        }
    }


    /**
     * flowRateControl 流速控制秒为维度
     */
    public function flowRateControl()
    {
        [$currentMillisecond, $currentSecond] = explode(' ', microtime());

        //记录的秒数时间和数量已经不在当前时间了则更新
        if ($currentSecond !== $this->currentSecond) {
            $this->currentFlowRate = 1;

            $this->currentSecond = $currentSecond;

            $this->currentHundredMillisecond = '0';

            return;
        }

        if ($this->type === 1) {
            //当前百位的毫秒数
            $currentHundredMillisecond = $currentMillisecond[2];

            if ($currentHundredMillisecond !== $this->currentHundredMillisecond) {
                $this->currentFlowRate = 1;

                $this->currentHundredMillisecond = $currentHundredMillisecond;

                return;
            }
        }

        //流速在范围内
        if (++$this->currentFlowRate < $this->maxFlowRate) {
            return;
        }

        //当前需要休眠的时间
        if ($this->type === 1) {
            $sleepTime = 0.1 - ('0.0'.$currentMillisecond[3].$currentMillisecond[4]);
        } else {
            $sleepTime = 1 - ('0.'.$currentMillisecond[2].$currentMillisecond[3].$currentMillisecond[4]);
        }


        if ($sleepTime >= 0.001) {
            //超过流速了则休眠
            Coroutine::sleep($sleepTime);
        }
    }
}

class GsmEncoder
{
    public static $dict = [
        '@' => "\x00", '£' => "\x01", '$' => "\x02", '¥' => "\x03", 'è' => "\x04", 'é' => "\x05", 'ù' => "\x06", 'ì' => "\x07", 'ò' => "\x08", 'Ç' => "\x09", 'Ø' => "\x0B", 'ø' => "\x0C", 'Å' => "\x0E", 'å' => "\x0F",
        'Δ' => "\x10", '_' => "\x11", 'Φ' => "\x12", 'Γ' => "\x13", 'Λ' => "\x14", 'Ω' => "\x15", 'Π' => "\x16", 'Ψ' => "\x17", 'Σ' => "\x18", 'Θ' => "\x19", 'Ξ' => "\x1A", 'Æ' => "\x1C", 'æ' => "\x1D", 'ß' => "\x1E", 'É' => "\x1F",
        '¡' => "\x40",
        'Ä' => "\x5B", 'Ö' => "\x5C", 'Ñ' => "\x5D", 'Ü' => "\x5E", '§' => "\x5F",
        '¿' => "\x60",
        'ä' => "\x7B", 'ö' => "\x7C", 'ñ' => "\x7D", 'ü' => "\x7E", 'à' => "\x7F",
        '^' => "\x1B\x14", '{' => "\x1B\x28", '}' => "\x1B\x29", '\\' => "\x1B\x2F", '[' => "\x1B\x3C", '~' => "\x1B\x3D", ']' => "\x1B\x3E", '|' => "\x1B\x40", '€' => "\x1B\x65",
    ];

    public static function utf8ToGsm0338($string)
    {
        return strtr($string, self::$dict);
    }

    public static function isGsm0338($utf8_string)
    {
        for ($i = 0; $i < mb_strlen($utf8_string); $i++) {
            $char = mb_substr($utf8_string, $i, 1);
            if (ord($char) > 0x7F && !isset(self::$dict[$char])) {
                return false;
            }
        }
        return true;
    }
}

trait TransmitterTrait
{
    protected $longSmsMark = 0;

    /**
     * submitSm
     * @param $srcId
     * @param $mobile
     * @param $text
     * @return array
     */
    public function submitSm($srcId, $mobile, $text)
    {
        //如果字节数超过254，则无法放在short_message字段中，可以通过三种方法解决
        //1.可通过message_payload参数一次行传输 https://smpp.org/SMPP_v3_4_Issue1_2.pdf 61页
        //2.通过sar_msg_ref_num，sar_total_segments，sar_segment_seqnum系列参数分片传输
        //3.通过将内容切分仍然放在short_message字段分片传输，这种需要配合ems_class设置为0x40进行传输（目前采用）
        if (GsmEncoder::isGsm0338($text)) {
            $dataEncoding = Smpp3Protocol::DATA_CODING_DEFAULT;

            $text = GsmEncoder::utf8ToGsm0338($text);

            //将采用gsm7编码
            if (strlen($text) > 160) {
                $splitMessages = str_split($text, 152);
                //市面上的gsm7貌似有问题以实际还是以八位传输
//                foreach ($splitMessages as $key => $message) {
//                    $splitMessages[$key] = Cmpp::packGsm7($message, 6);
//                }

                $esmClass = Smpp3Protocol::ESM_CLASS_UDHI;
            } else {
//                $splitMessages = [Cmpp::packGsm7($text, 0)];
                $splitMessages = [$text];

                $esmClass = 0;
            }

        } else {
            $dataEncoding = Smpp3Protocol::DATA_CODING_UCS2;

            $text = mb_convert_encoding($text, 'UCS-2', 'UTF-8');

            if (strlen($text) > 140) {
                $splitMessages = str_split($text, 132);

                $esmClass = Smpp3Protocol::ESM_CLASS_UDHI;
            } else {
                $splitMessages = [$text];

                $esmClass = 0;
            }
        }

        if ($esmClass === Smpp3Protocol::ESM_CLASS_UDHI) {
            $totalNum = count($splitMessages);

            $mark = $this->getLogSmsMark();

            foreach ($splitMessages as $index => $message) {
                $splitMessages[$index] = Smpp3Protocol::packLongSmsSlice($message, $mark, $totalNum, $index + 1);
            }
        }


        $sequenceNums = [];

        foreach ($splitMessages as $msg) {
            $this->flowRateControl();

            $sequenceNum = Smpp3Protocol::generateProSequenceId();

            $sequenceNums[] = $sequenceNum;

            $pdu = Smpp3Protocol::packSubmitSm($srcId, $mobile, $msg, $sequenceNum, $esmClass, $dataEncoding);

            $this->send($pdu);
        }

        return $sequenceNums;
    }

    /**
     * getLogSmsMark
     * @return int
     */
    protected function getLogSmsMark()
    {
        if (++$this->longSmsMark > 255) {
            $this->longSmsMark = 1;
        }

        return $this->longSmsMark;
    }
}

trait ReceiverTrait
{
    /**
     * handleDeliverSm
     * @param $sequenceNumber
     */
    public function handleDeliverSm($sequenceNumber)
    {
        $this->send(Smpp3Protocol::packDeliverSmResp($sequenceNumber));
    }
}

class Transceiver extends BaseTrans
{
    use FlowRate, TransmitterTrait, ReceiverTrait;

    public function __construct($smpp)
    {
        parent::__construct($smpp);

        $this->setMaxFlowRate($this->smpp->getConfig('submit_per_sec'));
    }

    /**
     * getBindPdu
     * @param $account
     * @param $pwd
     * @return string
     */
    public function getBindPdu($account, $pwd)
    {
        return Smpp3Protocol::packBindTransceiver(
            $account,
            $pwd,
            $this->smpp->getConfig('system_type'),
            $this->smpp->getConfig('interface_version'),
            $this->smpp->getConfig('addr_ton'),
            $this->smpp->getConfig('addr_npi'),
            $this->smpp->getConfig('address_range')
        );
    }

    /**
     * unpackBindResp
     * @param $pdu
     * @return array|bool
     */
    public function unpackBindResp($pdu)
    {
        $headerArr = Smpp3Protocol::unpackHeader(substr($pdu, 0, 16));

        if ($headerArr['command_id'] === Smpp3Protocol::BIND_RECEIVER_RESP) {
            return false;
        }

        $bodyArr = Smpp3Protocol::unpackBindResp(substr($pdu, 16));

        return array_merge($headerArr, $bodyArr);
    }

    /**
     * handlePdu
     * @param $pdu
     * @return array
     */
    public function handlePdu($pdu)
    {
        $headerArr = Smpp3Protocol::unpackHeader(substr($pdu, 0, 16));

        $this->resetSmscEnquireLikTime();

        //只返回submit_resp和deliver 其他的接收处理后跳过
        switch ($headerArr['command_id']) {
            case Smpp3Protocol::SUBMIT_SM_RESP:
                $data = Smpp3Protocol::unpackSubmitSmResp(substr($pdu, 16));

                if (empty($data)) {
                    break;
                }

                return array_merge($headerArr, $data);
            case Smpp3Protocol::DELIVER_SM:
                $data = Smpp3Protocol::unpackDeliverSm(substr($pdu, 16));

                if (empty($data)) {
                    break;
                }

                $this->handleDeliverSm($headerArr['sequence_number']);

                return array_merge($headerArr, $data);
            case Smpp3Protocol::ENQUIRE_LINK:
                $this->handleEnquireLink($headerArr['sequence_number']);

                break;
            case Smpp3Protocol::ENQUIRE_LINK_RESP:
                $this->handleEnquireLinkResp();

                break;
            case Smpp3Protocol::UNBIND:
                $this->handleUnbind($headerArr['sequence_number']);

                break;
            default:
                break;
        }

        return [];
    }

    /**
     * close
     */
    public function close()
    {
        $this->client->close();
    }
}

class Receiver extends BaseTrans
{
    use ReceiverTrait;

    /**
     * getBindPdu
     * @param $account
     * @param $pwd
     * @return string
     */
    public function getBindPdu($account, $pwd)
    {
        return Smpp3Protocol::packBindReceiver(
            $account,
            $pwd,
            $this->smpp->getConfig('system_type'),
            $this->smpp->getConfig('interface_version'),
            $this->smpp->getConfig('addr_ton'),
            $this->smpp->getConfig('addr_npi'),
            $this->smpp->getConfig('address_range')
        );
    }

    /**
     * unpackBindResp
     * @param $pdu
     * @return array|bool
     */
    public function unpackBindResp($pdu)
    {
        $headerArr = Smpp3Protocol::unpackHeader(substr($pdu, 0, 16));

        if ($headerArr['command_id'] !== Smpp3Protocol::BIND_RECEIVER_RESP) {
            return false;
        }

        $bodyArr = Smpp3Protocol::unpackBindResp(substr($pdu, 16));

        return array_merge($headerArr, $bodyArr);
    }

    /**
     * handlePdu
     * @param $pdu
     * @return array
     */
    public function handlePdu($pdu)
    {
        $headerArr = Smpp3Protocol::unpackHeader(substr($pdu, 0, 16));

        $this->resetSmscEnquireLikTime();

        //只返回submit_resp和deliver 其他的接收处理后跳过
        switch ($headerArr['command_id']) {
            case Smpp3Protocol::DELIVER_SM:
                $data = Smpp3Protocol::unpackDeliverSm(substr($pdu, 16));

                if (empty($data)) {
                    break;
                }

                $this->handleDeliverSm($headerArr['sequence_number']);

                return array_merge($headerArr, $data);
            case Smpp3Protocol::ENQUIRE_LINK:
                $this->handleEnquireLink($headerArr['sequence_number']);

                break;
            case Smpp3Protocol::ENQUIRE_LINK_RESP:
                $this->handleEnquireLinkResp();

                break;
            case Smpp3Protocol::UNBIND:
                $this->handleUnbind($headerArr['sequence_number']);

                break;
            default:
                break;
        }

        return [];
    }

    /**
     * close
     */
    public function close()
    {
        $this->client->close();

        $this->smpp->getTransmitter()->unbind();
    }
}

class Transmitter extends BaseTrans
{
    use FlowRate, TransmitterTrait;

    public function __construct($smpp)
    {
        parent::__construct($smpp);

        $this->setMaxFlowRate($this->smpp->getConfig('submit_per_sec'));
    }

    /**
     * getBindPdu
     * @param $account
     * @param $pwd
     * @return string
     */
    public function getBindPdu($account, $pwd)
    {
        return Smpp3Protocol::packBindTransmitter(
            $account,
            $pwd,
            $this->smpp->getConfig('system_type'),
            $this->smpp->getConfig('interface_version'),
            $this->smpp->getConfig('addr_ton'),
            $this->smpp->getConfig('addr_npi'),
            $this->smpp->getConfig('address_range')
        );
    }

    /**
     * unpackBindResp
     * @param $pdu
     * @return array|bool
     */
    public function unpackBindResp($pdu)
    {
        $headerArr = Smpp3Protocol::unpackHeader(substr($pdu, 0, 16));

        if ($headerArr['command_id'] === Smpp3Protocol::BIND_RECEIVER_RESP) {
            return false;
        }

        $bodyArr = Smpp3Protocol::unpackBindResp(substr($pdu, 16));

        return array_merge($headerArr, $bodyArr);
    }


    /**
     * handlePdu
     * @param $pdu
     * @return array
     */
    public function handlePdu($pdu)
    {
        $headerArr = Smpp3Protocol::unpackHeader(substr($pdu, 0, 16));

        $this->resetSmscEnquireLikTime();

        //只返回submit_resp和deliver 其他的接收处理后跳过
        switch ($headerArr['command_id']) {
            case Smpp3Protocol::SUBMIT_SM_RESP:
                $data = Smpp3Protocol::unpackSubmitSmResp(substr($pdu, 16));

                if (empty($data)) {
                    break;
                }

                return array_merge($headerArr, $data);
            case Smpp3Protocol::ENQUIRE_LINK:
                $this->handleEnquireLink($headerArr['sequence_number']);

                break;
            case Smpp3Protocol::ENQUIRE_LINK_RESP:
                $this->handleEnquireLinkResp();

                break;
            case Smpp3Protocol::UNBIND:
                $this->handleUnbind($headerArr['sequence_number']);

                break;
            default:
                break;
        }

        return [];
    }

    /**
     * close
     */
    public function close()
    {
        $this->client->close();

        $this->smpp->getReceiver()->unbind();
    }
}

class Smpp3Client
{
    /** @var Transceiver */
    protected $transceiver;
    /** @var Receiver */
    protected $receiver;
    /** @var Transmitter */
    protected $transmitter;

    protected $config;

    protected $sequenceNum;
    protected $startBindTime;

    public $errCode = 0;
    public $errMsg = '';

    /** @var Coroutine\Channel */
    protected $pduChannel;

    public function __construct($config)
    {
        $this->checkConfig($config);
    }

    /**
     * getChannel
     * @return Coroutine\Channel
     */
    public function getChannel()
    {
        return $this->pduChannel;
    }

    /**
     * getTransmitter
     * @return Transmitter
     */
    public function getTransmitter()
    {
        return $this->transmitter;
    }

    /**
     * getReceiver
     * @return Receiver
     */
    public function getReceiver()
    {
        return $this->receiver;
    }

    /**
     * getConfig
     * @param $key
     * @param  null  $default
     * @return mixed
     */
    public function getConfig($key, $default = null)
    {
        return $this->config[$key] ?? $default;
    }

    /**
     * getStartBindTime
     * @return mixed
     */
    public function getStartBindTime()
    {
        return $this->startBindTime;
    }

    /**
     * syncClientErr
     * @param $errCode
     * @param $errMsg
     */
    public function syncClientErr($errCode, $errMsg)
    {
        $this->errCode = $errCode;
        $this->errMsg  = $errMsg;
    }

    /**
     * checkConfig
     * @param $config
     */
    protected function checkConfig($config)
    {
        $config['system_type']       = empty($config['system_type']) ? 'WWW' : $config['system_type'];
        $config['interface_version'] = empty($config['interface_version']) ? 52 : (int) $config['interface_version'];
        $config['addr_ton']          = empty($config['addr_ton']) ? 1 : (int) $config['addr_ton'];
        $config['addr_npi']          = empty($config['addr_npi']) ? 1 : (int) $config['addr_npi'];
        $config['address_range']     = empty($config['address_range']) ? '' : $config['address_range'];

        $this->sequenceNum = $config['sequence_start'];
        $this->config      = $config;
    }


    /**
     * login
     * @param $ip
     * @param $port
     * @param $account
     * @param $pwd
     * @param $timeout
     * @return array|bool
     * @throws Exception
     */
    public function login($ip, $port, $account, $pwd, $timeout)
    {
        $this->startBindTime = time();

        if (strlen($account) > 15) {
            $this->syncClientErr(Smpp3Protocol::ESME_RINVSYSID, 'Invalid System ID');

            return false;
        }

        if (strlen($pwd) > 8) {
            $this->syncClientErr(Smpp3Protocol::ESME_RINVPASWD, 'Invalid Password');

            return false;
        }

        //接收一体模式
        $this->transceiver = new Transceiver($this);

        return $this->transceiver->bind(
            $ip, $port, $account, $pwd, $timeout,
            function () {
                //如果链接成功则创建探活
                Coroutine::create([$this->transceiver, 'doEnquireLink']);
            }
        );
        //接收分离模式
//            $this->transmitter = new Transmitter($this);
//
//            return $this->transmitter->bind(
//                $ip, $port, $account, $pwd, $timeout,
//                //成功则则创建receiver
//                $this->createReceiver(...func_get_args())
//            //不成功则返回bind的失败resp
//            );
    }

    /**
     * logout
     */
    public function logout()
    {
        $this->transceiver->unbind();
//            $this->transmitter->unbind();
//            $this->receiver->unbind();
    }

    /**
     * createReceiver
     * @param $ip
     * @param $port
     * @param $account
     * @param $pwd
     * @param $timeout
     * @return Closure
     */
    protected function createReceiver($ip, $port, $account, $pwd, $timeout)
    {
        return function () use ($ip, $port, $account, $pwd, $timeout) {
            //如果成功则需要进行receiver的bind
            $this->receiver = new Receiver($this);

            return $this->receiver->bind($ip, $port, $account, $pwd, $timeout, function () {
                //如果成功则创建两个客户端的探活
                Coroutine::create([$this->transmitter, 'doEnquireLink']);

                Coroutine::create([$this->receiver, 'doEnquireLink']);
            }, function () {
                //如果失败，则需要断开transmitter
                $this->transmitter->unbind();
            });
        };
    }

    /**
     * recv 暂时不设置超时有需要在弄
     * @param $timeout
     * @return bool|array
     */
    public function recv($timeout)
    {
        if (!isset($this->pduChannel)) {
            //创建pdu数据通道
            $this->pduChannel = new Coroutine\Channel(100000);

            Coroutine::create([$this->transceiver, 'recv']);
//                //只接收submit_resp
//                Coroutine::create([$this->transmitter, 'recv']);
//
//                //只接收deliver
//                Coroutine::create([$this->receiver, 'recv']);
        }

        return $this->pduChannel->pop($timeout);
    }

    /**
     * submit
     * @param $mobile
     * @param $text
     * @param $ext
     * @return array
     */
    public function submit($mobile, $text, $ext)
    {
        $client = $this->transceiver;
//            $client = $this->transmitter;

        return $client->submitSm($this->config['src_id_prefix'].$ext, $mobile, $text);
    }
}

$submitTime = $reportTime = [];

$mark = false;

Coroutine\run(function ()use ($portStr,$msgContent,$mobileStr) {
    $poolSize = $GLOBALS['argv'][1] ?? 20;
    //第一个参数是并发数
    $msgNum = $GLOBALS['argv'][2] ?? 1000;

    $GLOBALS['totalSubNum'] = $poolSize * $msgNum;

    //第二个参数是单个发送条数
    $GLOBALS['totalNum'] = 2 * $poolSize * $msgNum;

    $GLOBALS['startTime'] = time();

    $pool = [];

    for ($i = 0; $i < $poolSize; $i++) {
        $smpp = new Smpp3Client(
            [
                'sequence_start'       => $i * 100000,
                'sequence_end'         => 100000000, //在这个区间循环使用id，重新登录时候将从新在sequence_start开始
                'active_test_interval' => 100000000.5, //1.5s检测一次
                'active_test_num'      => 3, //10次连续失败就切断连接
                'service_id'           => "831948", //业务类型
                'src_id_prefix'        => "10690", //src_id的前缀+submit的扩展号就是整个src_id
                'submit_per_sec'       => 200, //每秒多少条限速，达到这个速率后submit会自动Co sleep这个协程，睡眠的时间按照剩余的时间来
                //例如每秒100，会分成10分，100ms最多发10条，如果前10ms就发送完了10条，submit的时候会自动Co sleep 90ms。
                'fee_type'             => '01', //资费类别
                'client_type'          => 1,
            ]
        );

        $arr = $smpp->login("127.0.0.1", $portStr, "641254", "f3749fdc", 10); //10s登录超时

        if ($arr !== false && $arr['command_status'] == 0) {
            var_dump('客户端'.$i.'：登陆成功，'.time());

            $pool[] = $smpp;

            Swoole\Coroutine::create(function () use ($smpp, $i) {
                while (true) {
                    //默认-1永不超时 直到有数据返回；
                    //只会收到submit回执包 或 delivery的请求包
                    $pack = $smpp->recv(-1);

                    if ($pack === false) {
                        if ($smpp->errCode === 8) {
                            var_dump('客户端'.$i.'：连接断开');
                            break;
                        } else {
                            continue;
                        }
                    }

                    if ($pack['command_id'] == Smpp3Protocol::SUBMIT_SM_RESP) {
                        @$GLOBALS['totalSubRespCnt']++;
                        if ($GLOBALS['totalSubRespCnt'] == $GLOBALS['totalSubNum']) {
                            $diff = time() - $GLOBALS['startTime'];
                            var_dump("发送结束 sub_resp 耗时 $diff");
                        }

                        $GLOBALS['submitTime'][time()] = ($GLOBALS['submitTime'][time()] ?? 0) + 1;

                        if ($pack['command_status'] === 0) {
                            $GLOBALS['totalNum']--;
                        } else {
                            $GLOBALS['totalNum']                          -= 2;
                            $GLOBALS['resp_err'][$pack['command_status']] = 1;
                        }
                    } elseif ($pack['registered_delivery'] === 1) {
                        @$GLOBALS['simuCnt']++;

                        @$GLOBALS['totalRepCnt']++;

                        if ($GLOBALS['totalRepCnt'] == $GLOBALS['totalSubNum']) {
                            $diff = time() - $GLOBALS['startTime'];
                            var_dump("发送结束 report 耗时 $diff");
                        }


                        $GLOBALS['reportTime'][time()] = ($GLOBALS['reportTime'][time()] ?? 0) + 1;
                        $GLOBALS['totalNum']--;
                        $GLOBALS['report_err'][$pack['short_message']['stat']] = 1;
                    }

                    if ($GLOBALS['totalNum'] <= 0) {
                        $GLOBALS['mark'] = true;
                    }
                }
            });
        } else {
            var_dump('客户端'.$i.'：登陆失败');
            var_dump($arr);

            foreach ($pool as $cmpp) {
                $cmpp->logout();
            }
        }
    }


    Coroutine::create(function () {
        while (true) {
            var_dump(@$GLOBALS['simuCnt']);
            Coroutine::sleep(1);
        }
    });

    Coroutine::create(function () use ($pool) {
        while (true) {
            if ($GLOBALS['mark']) {
                foreach ($pool as $cmpp) {
                    $cmpp->logout();
                }

                var_dump('submit response 返回分布时间分布：');

                foreach ($GLOBALS['submitTime'] as $time => $num) {
                    var_dump($time.':'.$num);
                }

                var_dump('report 返回分布时间分布：');

                foreach ($GLOBALS['reportTime'] as $time => $num) {
                    var_dump($time.':'.$num);
                }

                if (!empty($GLOBALS['resp_err'])) {
                    var_dump('response错误：');

                    var_dump(array_keys($GLOBALS['resp_err']));
                }

                if (!empty($GLOBALS['report_err'])) {
                    var_dump('report错误：');

                    var_dump(array_keys($GLOBALS['report_err']));
                }

                break;
            }

            Coroutine::sleep(1);
        }
    });

    $mobile = $mobileStr;

    foreach ($pool as $smpp) {
        Coroutine::create(function () use ($smpp, $msgNum, &$mobile, $msgContent) {
            $s = 0;
            for ($j = 0; $j < $msgNum; $j++) {
                $smpp->submit((string) $mobile, $msgContent, '0615', -1, ($s++) % 255); //默认-1 永不超时
                $mobile++;
            }

            var_dump('发送完毕，'.time());
        });
    }
});
