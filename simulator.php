<?php
/*
 * 解析配置文件
 */
$config = parse_ini_file("./config.ini");
if (empty($config)) {
    die("配置文件错误");
}

$portStr = $config['server_port'] ?? '';
if (empty($portStr)) {
    die("端口错误");
}

$reportStr = $config['report'] ?? '';
if (empty($reportStr) || strlen($reportStr) != 7) {
    die("状态错误");
}

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

class Smpp3Server
{
    public $allowCommands = [
        Smpp3Protocol::GENERIC_NACK,
        Smpp3Protocol::BIND_RECEIVER,
        Smpp3Protocol::BIND_TRANSMITTER,
        Smpp3Protocol::BIND_TRANSCEIVER,
        Smpp3Protocol::UNBIND,
        Smpp3Protocol::UNBIND_RESP,
        Smpp3Protocol::SUBMIT_SM,
        Smpp3Protocol::DELIVER_SM_RESP,
        Smpp3Protocol::ENQUIRE_LINK,
        Smpp3Protocol::ENQUIRE_LINK_RESP,
    ];
    public $notHandleCommands = [
        Smpp3Protocol::GENERIC_NACK,
        Smpp3Protocol::DELIVER_SM_RESP,
        Smpp3Protocol::UNBIND_RESP,
        Smpp3Protocol::ENQUIRE_LINK_RESP,
    ];
    public $needCloseFd = false;//是否需要关闭连接
    public $response;           //协议响应
    protected $commandId;       //协议动作
    protected $headerBinary;    //协议头
    protected $bodyBinary;      //协议头
    protected $headerArr;       //解析后的协议头
    protected $bodyArr;         //解析后的协议头
    protected $msgHexId;        //msg id的十六进制字符串表现
    protected $msgIdDecArr;     //十进制msgid数组
    private static $msgSequenceId = 0;

    public static function generateMsgSequenceId()
    {
        return ++self::$msgSequenceId;
    }


    public function setBinary(string $binary)
    {
        $this->headerBinary = substr($binary, 0, 16);
        $this->bodyBinary   = substr($binary, 16);
    }

    /**
     * getCommandId 获取协议动作
     * @return int
     */
    public function getCommandId()
    {
        return $this->commandId;
    }

    /**
     * getResponse 获取响应数据
     * @return string
     */
    public function getResponse()
    {
        return $this->response;
    }

    /**
     * getMsgHexId 获取十六进制的msg id
     * @return mixed
     */
    public function getMsgHexId()
    {
        return $this->msgHexId;
    }

    /**
     * getNeedCloseFd
     * @return bool
     */
    public function getNeedCloseFd()
    {
        return $this->needCloseFd;
    }

    /**
     * parseHeader 解析数据头部获取协议动作
     * @return bool
     */
    public function parseHeader()
    {
        $this->headerArr = @unpack(Smpp3Protocol::$headerUnpackRule, $this->headerBinary);

        $this->commandId = $this->headerArr['command_id'] ?? null;

        if (!in_array($this->commandId, $this->allowCommands)) {
            return false;
        }

        if ($this->headerArr['command_status'] !== Smpp3Protocol::ESME_ROK) {
            return false;
        }

        return true;
    }

    /**
     * getHeader 获取协议头
     * @param  string  $key
     * @param  string  $default
     * @return array|string
     */
    public function getHeader(string $key = '', string $default = '')
    {
        if (empty($key)) {
            return $this->headerArr;
        }

        return $this->headerArr[$key] ?? $default;
    }

    /**
     * getBody 获取协议体
     * @param  string  $key
     * @param $default
     * @return array|string
     */
    public function getBody(string $key = '', $default = '')
    {
        if (empty($key)) {
            return $this->bodyArr;
        }

        if (isset($this->bodyArr[$key])) {
            return $this->bodyArr[$key];
        }

        return $default;
    }

    /**
     * packageErrResp
     * @param $errCode
     */
    public function packageErrResp($errCode)
    {
        $seqNumber = $this->getHeader('sequence_number');

        switch ($this->commandId) {
            case Smpp3Protocol::BIND_RECEIVER:
                $this->response = Smpp3Protocol::packBindReceiverResp($errCode, $seqNumber);
                break;
            case Smpp3Protocol::BIND_TRANSMITTER:
                $this->response = Smpp3Protocol::packBindTransmitterResp($errCode, $seqNumber);
                break;
            case Smpp3Protocol::BIND_TRANSCEIVER:
                $this->response = Smpp3Protocol::packBindTransceiverResp($errCode, $seqNumber);
                break;
            case Smpp3Protocol::UNBIND:
                $this->response = Smpp3Protocol::packUnbindResp($errCode, $seqNumber);
                break;
            case Smpp3Protocol::SUBMIT_SM:
                $this->response = Smpp3Protocol::packSubmitSmResp($errCode, $seqNumber);
                break;
            case Smpp3Protocol::ENQUIRE_LINK:
                $this->response = Smpp3Protocol::packEnquireLinkResp($seqNumber);
                break;
        }
    }

    /**
     * parseBody 解析协议体
     * @return bool
     */
    public function parseBody()
    {
        //拆除连接和客户端探活操作无协议体
        if ($this->commandId === Smpp3Protocol::UNBIND || $this->commandId === Smpp3Protocol::ENQUIRE_LINK) {
            return true;
        }

        switch ($this->commandId) {
            case Smpp3Protocol::BIND_RECEIVER:
            case Smpp3Protocol::BIND_TRANSMITTER:
            case Smpp3Protocol::BIND_TRANSCEIVER:
                $this->bodyArr = Smpp3Protocol::unpackBind($this->bodyBinary);
                break;
            case Smpp3Protocol::SUBMIT_SM:
                $this->bodyArr = Smpp3Protocol::unpackSubmitSm($this->bodyBinary);
                break;
        }

        return true;
    }

    /**
     * handle 处理协议
     * @return bool
     * @throws Exception
     */
    public function handle()
    {
        switch ($this->commandId) {
            case Smpp3Protocol::BIND_RECEIVER:
            case Smpp3Protocol::BIND_TRANSMITTER:
            case Smpp3Protocol::BIND_TRANSCEIVER:
                //客户端提交的连接请求
                return $this->handleConnect();
            case Smpp3Protocol::SUBMIT_SM:
                //客户端提交的发送连接请求
                return $this->handleSubmit();
            case Smpp3Protocol::UNBIND:
                //客户端提交的断开连接请求
                return $this->handleUnbind();
            case Smpp3Protocol::ENQUIRE_LINK:
                //客户段提交的探活请求
                return $this->handleEnquireLink();
        }

        return false;
    }

    /**
     * handleConnect 处理连接
     * @return bool
     * @throws Exception
     */
    public function handleConnect()
    {
        $this->packageConnectResp();

        return true;
    }

    /**
     * packageConnectResp
     */
    public function packageConnectResp()
    {
        switch ($this->getCommandId()) {
            case Smpp3Protocol::BIND_RECEIVER:
                $commandId = Smpp3Protocol::BIND_RECEIVER_RESP;
                break;
            case Smpp3Protocol::BIND_TRANSMITTER:
                $commandId = Smpp3Protocol::BIND_TRANSMITTER_RESP;
                break;
            default:
                $commandId = Smpp3Protocol::BIND_TRANSCEIVER_RESP;
                break;
        }

        $this->response = Smpp3Protocol::packBindResp($commandId, null, $this->getHeader('sequence_number'), $this->getBody('system_id'));
    }

    /**
     * generateMsgIdArr 生成msgid二进制字符串，转换成八位的数组
     * @param $spId
     * @return array
     * TODO 放到扩展里面做提高性能
     */
    public static function generateMsgIdArr()
    {
        $msgId = self::generateMsgSequenceId();

        //转换成二进制字符串
        $msgIdStr = sprintf('%032s', decbin($msgId));

        //分割字符串为8位一组
        $msgIdBinary = str_split($msgIdStr, 8);

        //将二进制转换为十进制因为pack只认字符串10进制数为十进制数
        $decArr = [];//十进制
        $hexArr = [];//十六进制
        foreach ($msgIdBinary as $binary) {
            $dec      = bindec($binary);
            $decArr[] = $dec;
            $hexArr[] = str_pad(dechex($dec), 2, '0', STR_PAD_LEFT);
        }

        return [$decArr, $hexArr];
    }

    /**
     * handleSubmit 处理短信提交
     * @return bool
     * @throws Exception
     */
    public function handleSubmit()
    {
        //获取msgid二进制字符串
        [$this->msgIdDecArr, $hexArr] = self::generateMsgIdArr();

        $this->msgHexId = implode('', $hexArr);

        $this->response = Smpp3Protocol::packSubmitSmResp(null, $this->getHeader('sequence_number'), $this->msgHexId);

        return true;
    }

    /**
     * handleUnbind 处理客户端的断开连接请求
     * @return bool
     */
    public function handleUnbind()
    {
        $this->response = Smpp3Protocol::packUnbindResp($this->getHeader('sequence_number'));

        return true;
    }

    /**
     * handleEnquireLink 处理客户端探活
     * @return bool
     */
    public function handleEnquireLink()
    {
        $this->response = Smpp3Protocol::packEnquireLinkResp($this->getHeader('sequence_number'));

        return true;
    }

    /**
     * getRespCommand
     * @return int
     */
    public function getRespCommand()
    {
        if ($this->commandId === Smpp3Protocol::SUBMIT_SM) {
            return Smpp3Protocol::SUBMIT_SM_RESP;
        }

        return 0;
    }
}

$server = new Swoole\Server('0.0.0.0', $portStr);

$server->set([
        'worker_num'            => 1,
        'enable_coroutine'      => true,
        'open_length_check'     => true,
        'open_tcp_nodelay'      => true,
        'package_length_type'   => 'N',
        'package_length_offset' => 0,
        'package_body_offset'   => 0,
    ]
);

//监听连接进入事件
$server->on('Connect', function ($server, $fd) {
    echo "Client: Connect.\n";
});


//监听连接关闭事件
$server->on('Close', function ($server, $fd) {
    echo "Client: Close.\n";
});

$server->on('receive', function (Swoole\Server $server, $fd, $from_id, $data) use ($reportStr) {
    $protocol = new Smpp3Server();

    try {
        $protocol->setBinary($data);

        if (!$protocol->parseHeader()) {
            //解析协议头，不在允许的范围内返回公共错误
            $server->send($fd, Smpp3Protocol::packGenericNack(Smpp3Protocol::ESME_RINVCMDID, $protocol->getHeader('sequence_number')));

            return;
        }

        if (in_array($protocol->getCommandId(), $protocol->notHandleCommands)) {
            //如果是无需处理的
            return;
        }

        $handleRes = false;

        //解析协议体成功了，执行后续操作s
        if ($protocol->parseBody()) {
            $handleRes = $protocol->handle();
        }

        //发送resp同时确认是否关闭连接
        if ($server->exist($fd) && $handleRes) {
            $server->send($fd, $protocol->getResponse());
        }

        if ($protocol->getCommandId() === Smpp3Protocol::SUBMIT_SM && $handleRes) {
            $body = $protocol->getBody();

            $binary = Smpp3Protocol::packDeliverSm(
                Smpp3Protocol::ESM_CLASS_DELIVERY_REPORT,
                $body['source_addr'],
                $body['destination_addr'],
                ['id' => $protocol->getMsgHexId(), 'stat' => $reportStr, 'text' => '']
            );

            $server->send($fd, $binary);
        }
    } catch (Throwable $e) {
        var_dump($e->getMessage());
        if ($server->exist($fd)) {
            $server->send($fd, Smpp3Protocol::packGenericNack($e->getCode(), $protocol->getHeader('sequence_number')));
            //断开连接
            $server->close($fd);
        }
    }
});

//启动服务器
$server->start();
