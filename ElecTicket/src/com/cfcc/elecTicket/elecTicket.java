
package com.cfcc.elecTicket;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import com.cfcc.crs.CRSService;

public class elecTicket extends Applet
{

    RandomData g_randomData;// 随机数对象

    SecureChannel secCh;

    byte g_cardState;// 用于指示是否结束个人化

    byte[] g_randomBuffer;// 8字节

    public byte[] g_TempBuf;

    public Cipher g_cipherECB;// 加密对象

    public Cipher g_cipherCBC;// 加密对象

    public Signature m_mac;// mac对象

    public DESKey m_key16;// des key对象

    public byte[] NBKey;// 市民卡key数据

    public byte[] g_IRK1;// KEY1

    public byte[] g_IRK2;// KEY2

    public byte[] g_IRK1_head;// KEY1head ver+ID

    public byte[] g_IRK2_head;// KEY2head

    static final byte[] CRSIDS = { ( byte ) 0xA0, 0x00, 0x00, 0x01, 0x51, 0x43, 0x52, 0x53, 0x00 };

    private static final byte PROTOCOL_CONTACTLESS = ( byte ) (APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B);

    public byte[] NBEF01;// 健康卡文件1

    public byte[] NBEF0201;// 健康卡文件201

    public byte[] NBEF0202;// 健康卡文件201

    public byte[] NBEF0203;// 健康卡文件201

    public byte[] NBEF0204;// 健康卡文件201

    public byte[] NBEF0205;// 健康卡文件201

    // public byte[] NBEF0206;// 健康卡文件201
    //
    // public byte[] NBEF0207;// 健康卡文件201
    //
    // public byte[] NBEF0208;// 健康卡文件201
    //
    // public byte[] NBEF0209;// 健康卡文件201
    //
    // public byte[] NBEF020a;// 健康卡文件201
    //
    // public byte[] NBEF020b;// 健康卡文件201
    //
    // public byte[] NBEF020c;// 健康卡文件201
    //
    // public byte[] NBEF020d;// 健康卡文件201
    //
    // public byte[] NBEF020e;// 健康卡文件201
    //
    // public byte[] NBEF020f;// 健康卡文件201

    public short NBSFI1;// 记录连续读取时的sfi信息

    public byte NBReadflag;// 读取文件设置标记

    public byte NBRCflag;// 记录文件权限

    public byte NBWCflag;// 记录文件权限

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {

        // GP-compliant JavaCard applet registration
        new elecTicket().register(bArray, ( short ) (bOffset + 1), bArray[bOffset]);
    }

    public elecTicket()
    {

        g_randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);// 建立随机数对象
        g_randomBuffer = JCSystem.makeTransientByteArray(( short ) 0x08, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        g_TempBuf = JCSystem.makeTransientByteArray(( short ) 0x100, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        g_cipherECB = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);// 暂时采取不填充方式
        g_cipherCBC = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);// 暂时采取不填充方式
        m_key16 = ( DESKey ) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        m_mac = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3, false);

        // 市民卡应用密钥空间定义
        NBKey = new byte[] { ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00,
                        ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00,
                        ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00 };// 每条key为16字节内容+4字节控制字，共10条
        g_IRK1 = new byte[] { ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00,
                        ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00,
                        ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00 };
        g_IRK2 = new byte[] { ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00,
                        ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00,
                        ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00 };

        g_IRK1_head = new byte[] { ( byte ) 0x00, ( byte ) 0x01 };
        g_IRK2_head = new byte[] { ( byte ) 0x00, ( byte ) 0x02 };
        NBEF01 = new byte[16];
        NBEF0201 = new byte[150];
        NBEF0202 = new byte[150];
        NBEF0203 = new byte[150];
        NBEF0204 = new byte[150];
        NBEF0205 = new byte[150];
        // NBEF0206 = new byte[150];
        // NBEF0207 = new byte[150];
        // NBEF0208 = new byte[150];
        // NBEF0209 = new byte[150];
        // NBEF020a = new byte[150];
        // NBEF020b = new byte[150];
        // NBEF020c = new byte[150];
        // NBEF020d = new byte[150];
        // NBEF020e = new byte[150];
        // NBEF020f = new byte[150];

        NBSFI1 = 0;
        NBReadflag = 0;
        NBRCflag = 0;
        NBWCflag = 0;
        g_cardState = 0x00;// False
    }

    public void process(APDU apdu)
    {

         CRSService sioCRSService=null;
        try
        {
            sioCRSService = ( CRSService ) JCSystem.getAppletShareableInterfaceObject(JCSystem.lookupAID(CRSIDS,( short ) 0x00,( byte ) CRSIDS.length),( byte ) 0);
        }
        catch (Exception e)
        {
            sioCRSService=null;
        }
       
       
        // Good practice: Return 9000 on SELECT
        byte[] buf = apdu.getBuffer();
        
        buf[0] = (byte)(buf[0]&0xFC);
        
        short sw = ISO7816.SW_NO_ERROR;

        short len = 0;

        switch (buf[ISO7816.OFFSET_INS])
        {
            case ( byte ) 0xa4:// select
                if (buf[ISO7816.OFFSET_CLA] != ( byte ) 0x00)
                {
                    ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                    break;
                }
                if (buf[ISO7816.OFFSET_P1] != ( byte ) 0x04)
                {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                    break;
                }

                if (buf[ISO7816.OFFSET_P2] != ( byte ) 0x00)
                {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                    break;
                }

                // Good practice: Return 9000 on SELECT
                if (selectingApplet() == true)
                {

                    // 0 非接 1接触
                    if (( byte ) (APDU.getProtocol() & PROTOCOL_CONTACTLESS) == ( byte ) 0)
                    {
                        // ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                    }
                    else
                    {
                        if (null != sioCRSService)
                        {
                            short existed = sioCRSService.findAIDInList(buf, ( short ) 5, ( short ) buf[4]);
                            if (existed == ( short ) 0xffff)
                            {
                                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                                break;
                            }
                        }
                    }

                    sw = gProcessSelect(apdu);
                    return;
                }
                break;
            case ( byte ) 0x84:// 随机数
                sw = processGetChallange(apdu);
                break;
            case ( byte ) 0xB0:// 读取二进制文件
                sw = gReadBinary(apdu);
                break;
            case ( byte ) 0xd6:// 更新二进制文件
                sw = gProcessUpdateBinary(apdu);
                break;
            case ( byte ) 0xB2:// 读记录文件
                sw = processReadRecord(apdu);
                break;
            case ( byte ) 0xDC:// 更新记录文件
                sw = processUpdateRecord(apdu);
                break;
            case ( byte ) 0x82:// 外部认证
                if (buf[ISO7816.OFFSET_CLA] == ( byte ) 0x00)
                {
                    sw = gProcessExternalAuth(apdu);
                }// 外部认证
                else
                {
                    // secCh = GPSystem.getSecureChannel();
                    len = secCh.processSecurity(apdu);
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
                }
                break;
            case ( byte ) 0xF1:// write key by MTPS
                sw = gProcessWriteKey(apdu);
                break;
            case ( byte ) 0xD4:// write key by NB
                sw = gProcessWriteKeyNB(apdu);
                break;
            case ( byte ) 0x50:// 初始化update
                secCh = GPSystem.getSecureChannel();
                len = secCh.processSecurity(apdu);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
            case ( byte ) 0xe1:// 创建文件
                sw = ISO7816.SW_NO_ERROR;
                break;
            case ( byte ) 0x00:
                break;

            default:
                // good practice: If you don't know the INStruction, say so:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        if (sw != ISO7816.SW_NO_ERROR)
        {
            ISOException.throwIt(sw);
        }
    }

    private short gProcessSelect(APDU apdu)
    {

        byte[] buffer = apdu.getBuffer();

        // 状态寄存器复位
        NBSFI1 = 0;
        NBReadflag = 0;
        NBRCflag = 0;
        NBWCflag = 0;
        Util.arrayFillNonAtomic(g_randomBuffer, ( short ) 0x00, ( short ) 0x08, ( byte ) 0x00);

        // TODO:返回信息处理 700451020201
        buffer[0] = ( byte ) 0x70;
        buffer[1] = 0x04;
        buffer[2] = 0x51;
        buffer[3] = 0x02;
        buffer[4] = 0x02;
        buffer[5] = 0x01;

        apdu.setOutgoing();
        apdu.setOutgoingLength(( short ) (0x06));
        apdu.sendBytesLong(buffer, ( short ) 0x00, ( short ) (0x06));
        return ISO7816.SW_NO_ERROR;
    }

    private short gProcessExternalAuth(APDU apdu)
    {

        byte[] buffer;
        byte KID;
        byte result;
        buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        // 检查随机数是否存在

        if (buffer[ISO7816.OFFSET_P1] != ( byte ) 0x00)
        {
            return ISO7816.SW_WRONG_P1P2;
        }
        if (buffer[ISO7816.OFFSET_LC] != ( byte ) 0x08)
        {
            return ISO7816.SW_WRONG_LENGTH;
        }

        KID = buffer[ISO7816.OFFSET_P2];

        // 检查随机数是否存在
        if ((g_randomBuffer[0x00] == 0x00) && (g_randomBuffer[0x01] == 0x00))
        {
            return ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        if (buffer[ISO7816.OFFSET_CLA] != ( byte ) 0x00)
        {
            return ISO7816.SW_INS_NOT_SUPPORTED;
        }
        if (buffer[ISO7816.OFFSET_P2] != ( byte ) 0x03)
        {
            return ISO7816.SW_WRONG_P1P2;
        }
        if (buffer[ISO7816.OFFSET_LC] != ( byte ) 0x08)
        {
            return ISO7816.SW_WRONG_LENGTH;
        }
        // 找密钥 m_key16
        if (KID == 0x01)
        {
            m_key16.setKey(NBKey, ( short ) 0x00);
            g_cipherECB.init(m_key16, Cipher.MODE_ENCRYPT);
        }
        else if (KID == 0x02)
        {
            m_key16.setKey(g_IRK1, ( short ) 0x00);
            g_cipherECB.init(m_key16, Cipher.MODE_ENCRYPT);
        }
        else if (KID == 0x03)
        {
            m_key16.setKey(g_IRK2, ( short ) 0x00);
            g_cipherECB.init(m_key16, Cipher.MODE_ENCRYPT);
        }
        else
        {
            return ISO7816.SW_FILE_NOT_FOUND;
        }

        // 加密随机数
        // m_cipherECB.doFinal(data,(short)(offset),(short)len,dstdata,(short)(dstoffset));
        /*
         * g_randomBuffer[0]=0x11; g_randomBuffer[1]=(byte)0x11;
         * g_randomBuffer[2]=0x11; g_randomBuffer[3]=(byte)0x11;
         * g_randomBuffer[4]=0x11; g_randomBuffer[5]=(byte)0x11;
         * g_randomBuffer[6]=(byte)0x11; g_randomBuffer[7]=0x11;
         */
        // 计算KCV
        g_cipherECB.doFinal(g_randomBuffer, ( short ) 0x00, ( short ) 0x08, g_TempBuf, ( short ) (0x00));
        // 判断是否通过认证
        result = Util.arrayCompare(g_TempBuf, ( short ) 0x00, buffer, ISO7816.OFFSET_CDATA, ( short ) 0x08);
        // return
        // (short)(SW_REMAINING_PINLEFT|(short)(m_upcardFile.m_keyFileCollection.getKeyLeftNum()));
        if (result != 0x00)// 外部认证失败
        {

            NBRCflag = 0;
            NBWCflag = 0;

            return ISO7816.SW_CONDITIONS_NOT_SATISFIED;
        }
        else
        {
            if (KID == 0x02)
            {
                NBRCflag = 0x22;
                NBWCflag = 0x22;
            }
            else if (KID == 0x03)
            {
                NBRCflag = 0x33;
                NBWCflag = 0x33;
            }
            else
            {
            }
            Util.arrayFillNonAtomic(g_randomBuffer, ( short ) 0x00, ( short ) 0x08, ( byte ) 0x00);

        }
        return ISO7816.SW_NO_ERROR;
    }

    private short gReadBinary(APDU apdu)
    {

        byte[] buffer = apdu.getBuffer();
        short offset, fileSize;
        offset = 0;
        fileSize = 0;
        if (buffer[ISO7816.OFFSET_CLA] != ( byte ) 0x00)
        {
            return ISO7816.SW_CLA_NOT_SUPPORTED;
        }

        /*
         * P1字节定义:
         * --------------------------------------------------------------------
         * B8| B7 | B6 | B5 | B4 | B3 | B2 | B1 | 含义 |
         * --------------------------------------------------------------------
         * X | - | - | - | - | - | - | - | 读取模式 |
         * --------------------------------------------------------------------
         * 1 | | | | | | | | 用SFI方式 |
         * --------------------------------------------------------------------
         * - | 0 | 0 | | | | | | 用SFI方式时，必须为0 |
         * --------------------------------------------------------------------
         * - | - | - | X | X | X | X | X | SFI值 |
         * --------------------------------------------------------------------
         */
        // SFI的最高位为1，p2是偏移量信息
        if (( byte ) (buffer[ISO7816.OFFSET_P1] & 0xE0) == ( byte ) 0x80)// P1代表SFI信息
        {
            NBSFI1 = ( short ) (buffer[ISO7816.OFFSET_P1] & 0x1f);
            if ((NBSFI1 != ( byte ) 0x01))// SFI超出范围
            {
                return ISO7816.SW_WRONG_P1P2;
            }
            // 获取偏移量
            offset = ( short ) (buffer[ISO7816.OFFSET_P2] & 0xff);

        }
        else
        // P1,P2均为偏移量
        {
            offset = Util.getShort(buffer, ( short ) 0x02);
            // offset=(short)((buffer[ISO7816.OFFSET_P1]&0x1f)|(buffer[ISO7816.OFFSET_P2]&0xff));
        }
        // 判断读取权限是否达到

        // 判断是否超限
        if (offset + ( short ) (buffer[ISO7816.OFFSET_LC]) > 0x10)
        {
            return ( short ) 0x6282;
        }

        // 当Le为0时，要读的数据长度为文件大小减去偏移
        if (buffer[ISO7816.OFFSET_LC] == 0)
        {
            buffer[ISO7816.OFFSET_LC] = ( byte ) 0x10;
        }

        // 将文件内容独到buf中
        if (NBSFI1 == ( byte ) 0x01)// ef01
        {
            Util.arrayCopyNonAtomic(NBEF01, offset, g_TempBuf, ( short ) 0x00, ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
        }
        else
        {
        }

        apdu.setOutgoing();
        apdu.setOutgoingLength(( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
        apdu.sendBytesLong(g_TempBuf, ( short ) 0x00, ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
        return ISO7816.SW_NO_ERROR;
    }

    private short gProcessUpdateBinary(APDU apdu)
    {

        byte[] buffer;
        short offset;
        short lenSecCh = 0;
        short secChOffset;
        short secChLen;
        buffer = apdu.getBuffer();

        apdu.setIncomingAndReceive();
        /*
         * P1字节定义:
         * --------------------------------------------------------------------
         * B8| B7 | B6 | B5 | B4 | B3 | B2 | B1 | 含义 |
         * --------------------------------------------------------------------
         * X | - | - | - | - | - | - | - | 读取模式 |
         * --------------------------------------------------------------------
         * 1 | | | | | | | | 用SFI方式 |
         * --------------------------------------------------------------------
         * - | 0 | 0 | | | | | | 用SFI方式时，必须为0 |
         * --------------------------------------------------------------------
         * - | - | - | X | X | X | X | X | SFI值 |
         * --------------------------------------------------------------------
         */
        // SFI的最高位为1，p2是偏移量信息
        if (( byte ) (buffer[ISO7816.OFFSET_P1] & 0xE0) == ( byte ) 0x80)// P1代表SFI信息
        {
            NBSFI1 = ( short ) (buffer[ISO7816.OFFSET_P1] & 0x1f);
            if ((NBSFI1 != ( byte ) 0x01))// SFI超出范围
            {
                 return ISO7816.SW_WRONG_P1P2;
            }
            // 获取偏移量
            offset = ( short ) (buffer[ISO7816.OFFSET_P2] & 0xff);

        }
        else
        // P1,P2均为偏移量
        {
            offset = Util.getShort(buffer, ( short ) 0x02);
            // offset=(short)((short)((buffer[ISO7816.OFFSET_P1]&0x1f)<<2)|(short)(buffer[ISO7816.OFFSET_P2]&0xff));
        }
        // 获取指定文件大小

        // lc必须大于0
        if (buffer[ISO7816.OFFSET_LC] == 0)
        {
            return ISO7816.SW_WRONG_LENGTH;
        }

        if (buffer[ISO7816.OFFSET_CLA] == ( byte ) 0x84)
        {
            // 安全通道进行文件更新
            // SecureChannel secCh =
            // GPSystem.getSecureChannel();//获取安全通道句柄20130407 changying
            if ((secCh.getSecurityLevel() & SecureChannel.AUTHENTICATED) == 0)
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

            // 校验mac
            secChOffset = ( short ) 0x00;
            secChLen = ( short ) ((buffer[ISO7816.OFFSET_LC] & 0xff) + 0x05);
            lenSecCh = secCh.unwrap(buffer, secChOffset, secChLen);

            if (NBSFI1 == ( byte ) 0x01)
            {
                Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, NBEF01, offset, ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
            }
            else
            {
            }
            return ISO7816.SW_NO_ERROR;

        }

        // 偏移是否超出文件大小
        if (offset >= ( short ) 0x10)
        {
             return ISO7816.SW_WRONG_P1P2;
        }
        // 更新数据是否超界
        if ((offset + ( short ) buffer[ISO7816.OFFSET_LC]) > ( short ) 0x10)
        {
             return ISO7816.SW_WRONG_P1P2;
        }

        // 判断修改权限是否达到
        if (NBSFI1 == ( byte ) 0x01)
        {
            if (NBWCflag != ( byte ) 0x22)
            {
                return ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED;
            }
        }
        else
        {
        }

        // 更新文件
        // buffer[0x06]=0x66;
        // Util.arrayCopy(buffer, (short)ISO7816.OFFSET_CDATA, NBEF05, (short)0,
        // (short)0x33);
        if (NBSFI1 == ( byte ) 0x01)
        {
            Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, NBEF01, offset, ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
        }
        else
        {
        }

        return ISO7816.SW_NO_ERROR;
    }

    private short processReadRecord(APDU apdu)
    {

        byte[] buffer;

        buffer = apdu.getBuffer();

        /*
         * P2字节定义:
         * --------------------------------------------------------------------
         * B8| B7 | B6 | B5 | B4 | B3 | B2 | B1 | 含义 |
         * --------------------------------------------------------------------
         * X | X | X | X | X | - | - | - | SFI |
         * --------------------------------------------------------------------
         * - | - | - | - | - | 1 | 0 | 0 | 以记录号读取，P1为记录号 |
         * --------------------------------------------------------------------
         */

        NBSFI1 = ( byte ) (buffer[ISO7816.OFFSET_P2] >> 0x03);

        if (NBSFI1 != 0x02)//
        {
            return ISO7816.SW_FILE_NOT_FOUND;
        }

        // 文件类型检查

        // 读权限检查。

        if (buffer[ISO7816.OFFSET_P1] == 0x00)
        {
            // 文件记录未找到
            return ISO7816.SW_RECORD_NOT_FOUND;
        }

        if (buffer[ISO7816.OFFSET_P1] > 0x05)
        {
            // 文件记录未找到
            return ISO7816.SW_RECORD_NOT_FOUND;
        }

        // 当le为0时，读出文件全部数据
        if (buffer[ISO7816.OFFSET_LC] == 0x00)
        {
            buffer[ISO7816.OFFSET_LC] = ( byte ) 0x96;
        }
        else if (NBSFI1 == 0x02)
        {
            if (buffer[ISO7816.OFFSET_LC] != ( byte ) 0x96)
            {
                return ISO7816.SW_WRONG_LENGTH;
            }
        }
        else
        {
        }

        switch (buffer[ISO7816.OFFSET_P1])
        {
            case ( byte ) 0x01:
                Util.arrayCopyNonAtomic(NBEF0201,
                                        ( short ) 0,
                                        g_TempBuf,
                                        ( short ) 0,
                                        ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
                break;
            case ( byte ) 0x02:
                Util.arrayCopyNonAtomic(NBEF0202,
                                        ( short ) 0,
                                        g_TempBuf,
                                        ( short ) 0,
                                        ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
                break;
            case ( byte ) 0x03:
                Util.arrayCopyNonAtomic(NBEF0203,
                                        ( short ) 0,
                                        g_TempBuf,
                                        ( short ) 0,
                                        ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
                break;
            case ( byte ) 0x04:
                Util.arrayCopyNonAtomic(NBEF0204,
                                        ( short ) 0,
                                        g_TempBuf,
                                        ( short ) 0,
                                        ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
                break;
            case ( byte ) 0x05:
                Util.arrayCopyNonAtomic(NBEF0205,
                                        ( short ) 0,
                                        g_TempBuf,
                                        ( short ) 0,
                                        ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
                break;
            /**
             * case ( byte ) 0x06: Util.arrayCopyNonAtomic(NBEF0206, ( short )
             * 0, g_TempBuf, ( short ) 0, ( short ) (buffer[ISO7816.OFFSET_LC] &
             * 0xFF)); break; case ( byte ) 0x07:
             * Util.arrayCopyNonAtomic(NBEF0207, ( short ) 0, g_TempBuf, ( short
             * ) 0, ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF)); break; case (
             * byte ) 0x08: Util.arrayCopyNonAtomic(NBEF0208, ( short ) 0,
             * g_TempBuf, ( short ) 0, ( short ) (buffer[ISO7816.OFFSET_LC] &
             * 0xFF)); break; case ( byte ) 0x09:
             * Util.arrayCopyNonAtomic(NBEF0209, ( short ) 0, g_TempBuf, ( short
             * ) 0, ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF)); break; case (
             * byte ) 0x0a: Util.arrayCopyNonAtomic(NBEF020a, ( short ) 0,
             * g_TempBuf, ( short ) 0, ( short ) (buffer[ISO7816.OFFSET_LC] &
             * 0xFF)); break; case ( byte ) 0x0b:
             * Util.arrayCopyNonAtomic(NBEF020b, ( short ) 0, g_TempBuf, ( short
             * ) 0, ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF)); break; case (
             * byte ) 0x0c: Util.arrayCopyNonAtomic(NBEF020c, ( short ) 0,
             * g_TempBuf, ( short ) 0, ( short ) (buffer[ISO7816.OFFSET_LC] &
             * 0xFF)); break; case ( byte ) 0x0d:
             * Util.arrayCopyNonAtomic(NBEF020d, ( short ) 0, g_TempBuf, ( short
             * ) 0, ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF)); break; case (
             * byte ) 0x0e: Util.arrayCopyNonAtomic(NBEF020e, ( short ) 0,
             * g_TempBuf, ( short ) 0, ( short ) (buffer[ISO7816.OFFSET_LC] &
             * 0xFF)); break; case ( byte ) 0x0f:
             * Util.arrayCopyNonAtomic(NBEF020f, ( short ) 0, g_TempBuf, ( short
             * ) 0, ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF)); break;
             */
        }
        apdu.setOutgoing();
        apdu.setOutgoingLength(( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
        apdu.sendBytesLong(g_TempBuf, ( short ) 0x00, ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
        return ISO7816.SW_NO_ERROR;

    }

    // 更新记录文件
    private short processUpdateRecord(APDU apdu)
    {

        byte[] buffer;
        short sfi, tempLen;
        buffer = apdu.getBuffer();

        /*
         * P2字节定义:
         * --------------------------------------------------------------------
         * B8| B7 | B6 | B5 | B4 | B3 | B2 | B1 | 含义 |
         * --------------------------------------------------------------------
         * X | X | X | X | X | - | - | - | SFI |
         * --------------------------------------------------------------------
         * - | - | - | - | - | 1 | 0 | 0 | 以记录号读取，P1为记录号 |
         * --------------------------------------------------------------------
         */
        // 接收数据
        apdu.setIncomingAndReceive();

        if (buffer[ISO7816.OFFSET_LC] != ( byte ) 0x96)
        {
            return ISO7816.SW_WRONG_LENGTH;
        }
        if (buffer[ISO7816.OFFSET_LC] == 0x00)
        {
            return ISO7816.SW_WRONG_LENGTH;
        }

        NBSFI1 = ( byte ) ((buffer[ISO7816.OFFSET_P2] >> 0x03) & 0xFF);
        if (NBSFI1 != 0x02)
        {
            return ISO7816.SW_FILE_NOT_FOUND;
        }

        // 文件类型检查
        // 定长记录文件p1不等于0
        if (buffer[ISO7816.OFFSET_P1] == 0x00)
        {
            return ISO7816.SW_WRONG_P1P2;
        }

        // 写权限检查。
        if (NBWCflag != ( byte ) 0x33)
        {
            return ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED;
        }

        // TODO:01 02 03 模式
        // 当前模式
        switch (buffer[ISO7816.OFFSET_P1])
        {
            case ( byte ) 0x01:
                Util.arrayCopy(buffer,
                               ( short ) (ISO7816.OFFSET_CDATA),
                               NBEF0201,
                               ( short ) 0,
                               ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
                break;
            case ( byte ) 0x02:
                Util.arrayCopy(buffer,
                               ( short ) (ISO7816.OFFSET_CDATA),
                               NBEF0202,
                               ( short ) 0,
                               ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
                break;
            case ( byte ) 0x03:
                Util.arrayCopy(buffer,
                               ( short ) (ISO7816.OFFSET_CDATA),
                               NBEF0203,
                               ( short ) 0,
                               ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
                break;
            case ( byte ) 0x04:
                Util.arrayCopy(buffer,
                               ( short ) (ISO7816.OFFSET_CDATA),
                               NBEF0204,
                               ( short ) 0,
                               ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
                break;
            case ( byte ) 0x05:
                Util.arrayCopy(buffer,
                               ( short ) (ISO7816.OFFSET_CDATA),
                               NBEF0205,
                               ( short ) 0,
                               ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF));
                break;
            /**
             * case ( byte ) 0x06: Util.arrayCopy(buffer, ( short )
             * (ISO7816.OFFSET_CDATA), NBEF0206, ( short ) 0, ( short )
             * (buffer[ISO7816.OFFSET_LC] & 0xFF)); break; case ( byte ) 0x07:
             * Util.arrayCopy(buffer, ( short ) (ISO7816.OFFSET_CDATA),
             * NBEF0207, ( short ) 0, ( short ) (buffer[ISO7816.OFFSET_LC] &
             * 0xFF)); break; case ( byte ) 0x08: Util.arrayCopy(buffer, ( short
             * ) (ISO7816.OFFSET_CDATA), NBEF0208, ( short ) 0, ( short )
             * (buffer[ISO7816.OFFSET_LC] & 0xFF)); break; case ( byte ) 0x09:
             * Util.arrayCopy(buffer, ( short ) (ISO7816.OFFSET_CDATA),
             * NBEF0209, ( short ) 0, ( short ) (buffer[ISO7816.OFFSET_LC] &
             * 0xFF)); break; case ( byte ) 0x0a: Util.arrayCopy(buffer, ( short
             * ) (ISO7816.OFFSET_CDATA), NBEF020a, ( short ) 0, ( short )
             * (buffer[ISO7816.OFFSET_LC] & 0xFF)); break; case ( byte ) 0x0b:
             * Util.arrayCopy(buffer, ( short ) (ISO7816.OFFSET_CDATA),
             * NBEF020b, ( short ) 0, ( short ) (buffer[ISO7816.OFFSET_LC] &
             * 0xFF)); break; case ( byte ) 0x0c: Util.arrayCopy(buffer, ( short
             * ) (ISO7816.OFFSET_CDATA), NBEF020c, ( short ) 0, ( short )
             * (buffer[ISO7816.OFFSET_LC] & 0xFF)); break; case ( byte ) 0x0d:
             * Util.arrayCopy(buffer, ( short ) (ISO7816.OFFSET_CDATA),
             * NBEF020d, ( short ) 0, ( short ) (buffer[ISO7816.OFFSET_LC] &
             * 0xFF)); break; case ( byte ) 0x0e: Util.arrayCopy(buffer, ( short
             * ) (ISO7816.OFFSET_CDATA), NBEF020e, ( short ) 0, ( short )
             * (buffer[ISO7816.OFFSET_LC] & 0xFF)); break; case ( byte ) 0x0f:
             * Util.arrayCopy(buffer, ( short ) (ISO7816.OFFSET_CDATA),
             * NBEF020f, ( short ) 0, ( short ) (buffer[ISO7816.OFFSET_LC] &
             * 0xFF)); break;
             */
            default:
                ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }

        return ISO7816.SW_NO_ERROR;
    }

    private short gProcessWriteKey(APDU apdu)
    {

        byte[] buffer;
        byte KID, alg, len;
        short lenSecCh = 0;
        short secChOffset;
        short secChLen;
        buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        if ((buffer[ISO7816.OFFSET_CLA] != ( byte ) 0x80) && (buffer[ISO7816.OFFSET_CLA] != ( byte ) 0x84))
        {
            return ISO7816.SW_INS_NOT_SUPPORTED;
        }
        KID = buffer[ISO7816.OFFSET_P2];

        if ((secCh.getSecurityLevel() & SecureChannel.AUTHENTICATED) == 0)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        // 校验mac

        secChOffset = ( short ) 0x00;
        secChLen = ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        lenSecCh = secCh.unwrap(buffer, secChOffset, ( short ) (secChLen + 5));

        // 解密
        secChOffset = ( short ) (ISO7816.OFFSET_CDATA);
        secChLen = ( short ) (buffer[ISO7816.OFFSET_LC] & 0xff);
        lenSecCh = secCh.decryptData(buffer, secChOffset, ( short ) (secChLen - 3));

        Util.arrayCopy(buffer, ( short ) ISO7816.OFFSET_CDATA, g_TempBuf, ( short ) 0, buffer[ISO7816.OFFSET_LC]);

        if (KID == 0x01)// key1
        {

            Util.arrayCopy(g_TempBuf, ( short ) 0, NBKey, ( short ) 0, ( short ) 0x10);
        }
        else if (KID == 0x02)
        {

            Util.arrayCopy(g_TempBuf, ( short ) 0, g_IRK1, ( short ) 0, ( short ) 0x10);
        }
        else if (KID == 0x03)
        {

            Util.arrayCopy(g_TempBuf, ( short ) 0, g_IRK2, ( short ) 0, ( short ) 0x10);
        }
        else
        {
        }
        // /
        /*
         * apdu.setOutgoing(); apdu.setOutgoingLength((short)0x10);
         * 
         * if(KID == 0x01) { apdu.sendBytesLong(NBKey,(short)0x00,(short)
         * (0x10)); } else if(KID==0x02) {
         * apdu.sendBytesLong(g_IRK1,(short)0x00,(short) (0x10)); } else {
         * apdu.sendBytesLong(g_IRK2,(short)0x00,(short) (0x10)); } ///
         */
        return ISO7816.SW_NO_ERROR;
    }

    private short gProcessWriteKeyNB(APDU apdu)
    {

        byte[] buffer;
        byte KID;
        buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        if ((buffer[ISO7816.OFFSET_CLA] != ( byte ) 0x80) && (buffer[ISO7816.OFFSET_CLA] != ( byte ) 0x84))
        {
            return ISO7816.SW_INS_NOT_SUPPORTED;
        }
        KID = buffer[ISO7816.OFFSET_P2];

        // 解密新key
        if (KID == 0x01)
        {
            m_key16.setKey(NBKey, ( short ) 0x00);
        }
        else if (KID == 0x02)
        {
            m_key16.setKey(g_IRK1, ( short ) 0x00);
        }
        else if (KID == 0x03)
        {
            m_key16.setKey(g_IRK2, ( short ) 0x00);
        }
        else
        {
        }
        g_cipherECB.init(m_key16, Cipher.MODE_DECRYPT);
        g_cipherECB.doFinal(buffer,
                            ISO7816.OFFSET_CDATA,
                            ( short ) (buffer[ISO7816.OFFSET_LC] - 3),
                            g_TempBuf,
                            ( short ) (0x00));
        // 校验KCV
        Util.arrayFillNonAtomic(g_randomBuffer, ( short ) 0x00, ( short ) 0x08, ( byte ) 0x00);// 8字节随机数00

        m_key16.setKey(g_TempBuf, ( short ) 0x00);
        g_cipherECB.init(m_key16, Cipher.MODE_ENCRYPT);
        g_cipherECB.doFinal(g_randomBuffer, ( short ) 0x00, ( short ) 0x08, g_TempBuf, ( short ) 0x20);

        if (Util.arrayCompare(buffer,
                              ( short ) (ISO7816.OFFSET_CDATA + buffer[ISO7816.OFFSET_LC] - 3),
                              g_TempBuf,
                              ( short ) 0x20,
                              ( short ) 0x03) != 0)
        {
            return ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        // 通过
        if (KID == 0x01)// key1
        {
            Util.arrayCopy(g_TempBuf, ( short ) 0, NBKey, ( short ) 0, ( short ) 0x10);
        }
        else if (KID == 0x02)
        {

            Util.arrayCopy(g_TempBuf, ( short ) 0, g_IRK1, ( short ) 0, ( short ) 0x10);
        }
        else if (KID == 0x03)
        {

            Util.arrayCopy(g_TempBuf, ( short ) 0, g_IRK2, ( short ) 0, ( short ) 0x10);
        }
        else
        {
        }
        // /
        /*
         * apdu.setOutgoing(); apdu.setOutgoingLength((short)0x10);
         * 
         * if(KID == 0x01) { apdu.sendBytesLong(NBKey,(short)0x00,(short)
         * (0x10)); } else if(KID==0x02) {
         * apdu.sendBytesLong(g_IRK1,(short)0x00,(short) (0x10)); } else {
         * apdu.sendBytesLong(g_IRK2,(short)0x00,(short) (0x10)); } ///
         */
        return ISO7816.SW_NO_ERROR;
    }

    private short processGetChallange(APDU apdu)
    {

        byte[] buf;
        buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0)
        {
            return ISO7816.SW_WRONG_P1P2;
        }
        if ((buf[ISO7816.OFFSET_LC] != 0x08) && buf[ISO7816.OFFSET_LC] != 0x04)
        {
            return ISO7816.SW_WRONG_LENGTH;
        }
        // 随机数buffer填充00
        Util.arrayFillNonAtomic(g_randomBuffer, ( short ) 0x00, ( short ) 0x08, ( byte ) 0x00);
        // 取随机数
        g_randomData.generateData(g_randomBuffer, ( short ) 0, buf[ISO7816.OFFSET_LC]);

        apdu.setOutgoing();
        apdu.setOutgoingLength(buf[ISO7816.OFFSET_LC]);
        apdu.sendBytesLong(g_randomBuffer, ( short ) 0x00, buf[ISO7816.OFFSET_LC]);

        return ISO7816.SW_NO_ERROR;

    }
}
