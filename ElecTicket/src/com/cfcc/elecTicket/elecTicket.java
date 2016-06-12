
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

    RandomData g_randomData;// ���������

    SecureChannel secCh;

    byte g_cardState;// ����ָʾ�Ƿ�������˻�

    byte[] g_randomBuffer;// 8�ֽ�

    public byte[] g_TempBuf;

    public Cipher g_cipherECB;// ���ܶ���

    public Cipher g_cipherCBC;// ���ܶ���

    public Signature m_mac;// mac����

    public DESKey m_key16;// des key����

    public byte[] NBKey;// ����key����

    public byte[] g_IRK1;// KEY1

    public byte[] g_IRK2;// KEY2

    public byte[] g_IRK1_head;// KEY1head ver+ID

    public byte[] g_IRK2_head;// KEY2head

    static final byte[] CRSIDS = { ( byte ) 0xA0, 0x00, 0x00, 0x01, 0x51, 0x43, 0x52, 0x53, 0x00 };

    private static final byte PROTOCOL_CONTACTLESS = ( byte ) (APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B);

    public byte[] NBEF01;// �������ļ�1

    public byte[] NBEF0201;// �������ļ�201

    public byte[] NBEF0202;// �������ļ�201

    public byte[] NBEF0203;// �������ļ�201

    public byte[] NBEF0204;// �������ļ�201

    public byte[] NBEF0205;// �������ļ�201

    // public byte[] NBEF0206;// �������ļ�201
    //
    // public byte[] NBEF0207;// �������ļ�201
    //
    // public byte[] NBEF0208;// �������ļ�201
    //
    // public byte[] NBEF0209;// �������ļ�201
    //
    // public byte[] NBEF020a;// �������ļ�201
    //
    // public byte[] NBEF020b;// �������ļ�201
    //
    // public byte[] NBEF020c;// �������ļ�201
    //
    // public byte[] NBEF020d;// �������ļ�201
    //
    // public byte[] NBEF020e;// �������ļ�201
    //
    // public byte[] NBEF020f;// �������ļ�201

    public short NBSFI1;// ��¼������ȡʱ��sfi��Ϣ

    public byte NBReadflag;// ��ȡ�ļ����ñ��

    public byte NBRCflag;// ��¼�ļ�Ȩ��

    public byte NBWCflag;// ��¼�ļ�Ȩ��

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {

        // GP-compliant JavaCard applet registration
        new elecTicket().register(bArray, ( short ) (bOffset + 1), bArray[bOffset]);
    }

    public elecTicket()
    {

        g_randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);// �������������
        g_randomBuffer = JCSystem.makeTransientByteArray(( short ) 0x08, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        g_TempBuf = JCSystem.makeTransientByteArray(( short ) 0x100, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        g_cipherECB = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);// ��ʱ��ȡ����䷽ʽ
        g_cipherCBC = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);// ��ʱ��ȡ����䷽ʽ
        m_key16 = ( DESKey ) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        m_mac = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3, false);

        // ����Ӧ����Կ�ռ䶨��
        NBKey = new byte[] { ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00,
                        ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00,
                        ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00 };// ÿ��keyΪ16�ֽ�����+4�ֽڿ����֣���10��
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

                    // 0 �ǽ� 1�Ӵ�
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
            case ( byte ) 0x84:// �����
                sw = processGetChallange(apdu);
                break;
            case ( byte ) 0xB0:// ��ȡ�������ļ�
                sw = gReadBinary(apdu);
                break;
            case ( byte ) 0xd6:// ���¶������ļ�
                sw = gProcessUpdateBinary(apdu);
                break;
            case ( byte ) 0xB2:// ����¼�ļ�
                sw = processReadRecord(apdu);
                break;
            case ( byte ) 0xDC:// ���¼�¼�ļ�
                sw = processUpdateRecord(apdu);
                break;
            case ( byte ) 0x82:// �ⲿ��֤
                if (buf[ISO7816.OFFSET_CLA] == ( byte ) 0x00)
                {
                    sw = gProcessExternalAuth(apdu);
                }// �ⲿ��֤
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
            case ( byte ) 0x50:// ��ʼ��update
                secCh = GPSystem.getSecureChannel();
                len = secCh.processSecurity(apdu);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
            case ( byte ) 0xe1:// �����ļ�
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

        // ״̬�Ĵ�����λ
        NBSFI1 = 0;
        NBReadflag = 0;
        NBRCflag = 0;
        NBWCflag = 0;
        Util.arrayFillNonAtomic(g_randomBuffer, ( short ) 0x00, ( short ) 0x08, ( byte ) 0x00);

        // TODO:������Ϣ���� 700451020201
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
        // ���������Ƿ����

        if (buffer[ISO7816.OFFSET_P1] != ( byte ) 0x00)
        {
            return ISO7816.SW_WRONG_P1P2;
        }
        if (buffer[ISO7816.OFFSET_LC] != ( byte ) 0x08)
        {
            return ISO7816.SW_WRONG_LENGTH;
        }

        KID = buffer[ISO7816.OFFSET_P2];

        // ���������Ƿ����
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
        // ����Կ m_key16
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

        // ���������
        // m_cipherECB.doFinal(data,(short)(offset),(short)len,dstdata,(short)(dstoffset));
        /*
         * g_randomBuffer[0]=0x11; g_randomBuffer[1]=(byte)0x11;
         * g_randomBuffer[2]=0x11; g_randomBuffer[3]=(byte)0x11;
         * g_randomBuffer[4]=0x11; g_randomBuffer[5]=(byte)0x11;
         * g_randomBuffer[6]=(byte)0x11; g_randomBuffer[7]=0x11;
         */
        // ����KCV
        g_cipherECB.doFinal(g_randomBuffer, ( short ) 0x00, ( short ) 0x08, g_TempBuf, ( short ) (0x00));
        // �ж��Ƿ�ͨ����֤
        result = Util.arrayCompare(g_TempBuf, ( short ) 0x00, buffer, ISO7816.OFFSET_CDATA, ( short ) 0x08);
        // return
        // (short)(SW_REMAINING_PINLEFT|(short)(m_upcardFile.m_keyFileCollection.getKeyLeftNum()));
        if (result != 0x00)// �ⲿ��֤ʧ��
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
         * P1�ֽڶ���:
         * --------------------------------------------------------------------
         * B8| B7 | B6 | B5 | B4 | B3 | B2 | B1 | ���� |
         * --------------------------------------------------------------------
         * X | - | - | - | - | - | - | - | ��ȡģʽ |
         * --------------------------------------------------------------------
         * 1 | | | | | | | | ��SFI��ʽ |
         * --------------------------------------------------------------------
         * - | 0 | 0 | | | | | | ��SFI��ʽʱ������Ϊ0 |
         * --------------------------------------------------------------------
         * - | - | - | X | X | X | X | X | SFIֵ |
         * --------------------------------------------------------------------
         */
        // SFI�����λΪ1��p2��ƫ������Ϣ
        if (( byte ) (buffer[ISO7816.OFFSET_P1] & 0xE0) == ( byte ) 0x80)// P1����SFI��Ϣ
        {
            NBSFI1 = ( short ) (buffer[ISO7816.OFFSET_P1] & 0x1f);
            if ((NBSFI1 != ( byte ) 0x01))// SFI������Χ
            {
                return ISO7816.SW_WRONG_P1P2;
            }
            // ��ȡƫ����
            offset = ( short ) (buffer[ISO7816.OFFSET_P2] & 0xff);

        }
        else
        // P1,P2��Ϊƫ����
        {
            offset = Util.getShort(buffer, ( short ) 0x02);
            // offset=(short)((buffer[ISO7816.OFFSET_P1]&0x1f)|(buffer[ISO7816.OFFSET_P2]&0xff));
        }
        // �ж϶�ȡȨ���Ƿ�ﵽ

        // �ж��Ƿ���
        if (offset + ( short ) (buffer[ISO7816.OFFSET_LC]) > 0x10)
        {
            return ( short ) 0x6282;
        }

        // ��LeΪ0ʱ��Ҫ�������ݳ���Ϊ�ļ���С��ȥƫ��
        if (buffer[ISO7816.OFFSET_LC] == 0)
        {
            buffer[ISO7816.OFFSET_LC] = ( byte ) 0x10;
        }

        // ���ļ����ݶ���buf��
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
         * P1�ֽڶ���:
         * --------------------------------------------------------------------
         * B8| B7 | B6 | B5 | B4 | B3 | B2 | B1 | ���� |
         * --------------------------------------------------------------------
         * X | - | - | - | - | - | - | - | ��ȡģʽ |
         * --------------------------------------------------------------------
         * 1 | | | | | | | | ��SFI��ʽ |
         * --------------------------------------------------------------------
         * - | 0 | 0 | | | | | | ��SFI��ʽʱ������Ϊ0 |
         * --------------------------------------------------------------------
         * - | - | - | X | X | X | X | X | SFIֵ |
         * --------------------------------------------------------------------
         */
        // SFI�����λΪ1��p2��ƫ������Ϣ
        if (( byte ) (buffer[ISO7816.OFFSET_P1] & 0xE0) == ( byte ) 0x80)// P1����SFI��Ϣ
        {
            NBSFI1 = ( short ) (buffer[ISO7816.OFFSET_P1] & 0x1f);
            if ((NBSFI1 != ( byte ) 0x01))// SFI������Χ
            {
                 return ISO7816.SW_WRONG_P1P2;
            }
            // ��ȡƫ����
            offset = ( short ) (buffer[ISO7816.OFFSET_P2] & 0xff);

        }
        else
        // P1,P2��Ϊƫ����
        {
            offset = Util.getShort(buffer, ( short ) 0x02);
            // offset=(short)((short)((buffer[ISO7816.OFFSET_P1]&0x1f)<<2)|(short)(buffer[ISO7816.OFFSET_P2]&0xff));
        }
        // ��ȡָ���ļ���С

        // lc�������0
        if (buffer[ISO7816.OFFSET_LC] == 0)
        {
            return ISO7816.SW_WRONG_LENGTH;
        }

        if (buffer[ISO7816.OFFSET_CLA] == ( byte ) 0x84)
        {
            // ��ȫͨ�������ļ�����
            // SecureChannel secCh =
            // GPSystem.getSecureChannel();//��ȡ��ȫͨ�����20130407 changying
            if ((secCh.getSecurityLevel() & SecureChannel.AUTHENTICATED) == 0)
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

            // У��mac
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

        // ƫ���Ƿ񳬳��ļ���С
        if (offset >= ( short ) 0x10)
        {
             return ISO7816.SW_WRONG_P1P2;
        }
        // ���������Ƿ񳬽�
        if ((offset + ( short ) buffer[ISO7816.OFFSET_LC]) > ( short ) 0x10)
        {
             return ISO7816.SW_WRONG_P1P2;
        }

        // �ж��޸�Ȩ���Ƿ�ﵽ
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

        // �����ļ�
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
         * P2�ֽڶ���:
         * --------------------------------------------------------------------
         * B8| B7 | B6 | B5 | B4 | B3 | B2 | B1 | ���� |
         * --------------------------------------------------------------------
         * X | X | X | X | X | - | - | - | SFI |
         * --------------------------------------------------------------------
         * - | - | - | - | - | 1 | 0 | 0 | �Լ�¼�Ŷ�ȡ��P1Ϊ��¼�� |
         * --------------------------------------------------------------------
         */

        NBSFI1 = ( byte ) (buffer[ISO7816.OFFSET_P2] >> 0x03);

        if (NBSFI1 != 0x02)//
        {
            return ISO7816.SW_FILE_NOT_FOUND;
        }

        // �ļ����ͼ��

        // ��Ȩ�޼�顣

        if (buffer[ISO7816.OFFSET_P1] == 0x00)
        {
            // �ļ���¼δ�ҵ�
            return ISO7816.SW_RECORD_NOT_FOUND;
        }

        if (buffer[ISO7816.OFFSET_P1] > 0x05)
        {
            // �ļ���¼δ�ҵ�
            return ISO7816.SW_RECORD_NOT_FOUND;
        }

        // ��leΪ0ʱ�������ļ�ȫ������
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

    // ���¼�¼�ļ�
    private short processUpdateRecord(APDU apdu)
    {

        byte[] buffer;
        short sfi, tempLen;
        buffer = apdu.getBuffer();

        /*
         * P2�ֽڶ���:
         * --------------------------------------------------------------------
         * B8| B7 | B6 | B5 | B4 | B3 | B2 | B1 | ���� |
         * --------------------------------------------------------------------
         * X | X | X | X | X | - | - | - | SFI |
         * --------------------------------------------------------------------
         * - | - | - | - | - | 1 | 0 | 0 | �Լ�¼�Ŷ�ȡ��P1Ϊ��¼�� |
         * --------------------------------------------------------------------
         */
        // ��������
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

        // �ļ����ͼ��
        // ������¼�ļ�p1������0
        if (buffer[ISO7816.OFFSET_P1] == 0x00)
        {
            return ISO7816.SW_WRONG_P1P2;
        }

        // дȨ�޼�顣
        if (NBWCflag != ( byte ) 0x33)
        {
            return ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED;
        }

        // TODO:01 02 03 ģʽ
        // ��ǰģʽ
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

        // У��mac

        secChOffset = ( short ) 0x00;
        secChLen = ( short ) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        lenSecCh = secCh.unwrap(buffer, secChOffset, ( short ) (secChLen + 5));

        // ����
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

        // ������key
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
        // У��KCV
        Util.arrayFillNonAtomic(g_randomBuffer, ( short ) 0x00, ( short ) 0x08, ( byte ) 0x00);// 8�ֽ������00

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
        // ͨ��
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
        // �����buffer���00
        Util.arrayFillNonAtomic(g_randomBuffer, ( short ) 0x00, ( short ) 0x08, ( byte ) 0x00);
        // ȡ�����
        g_randomData.generateData(g_randomBuffer, ( short ) 0, buf[ISO7816.OFFSET_LC]);

        apdu.setOutgoing();
        apdu.setOutgoingLength(buf[ISO7816.OFFSET_LC]);
        apdu.sendBytesLong(g_randomBuffer, ( short ) 0x00, buf[ISO7816.OFFSET_LC]);

        return ISO7816.SW_NO_ERROR;

    }
}
