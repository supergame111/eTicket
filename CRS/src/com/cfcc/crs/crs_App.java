package com.cfcc.crs;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;

/**
 * @author Administrator
 * 
 */
public class crs_App extends Applet implements CRSService {

	static final byte INS_SET_STATUS = (byte) 0xF0;

	static final byte INS_GET_STATUS = (byte) 0xF2;

	// P1
	static final byte TYPE_GET_STATUS_APPLICATION = (byte) 0x40;

	static final short SW_PPSE_IS_NOT_INSTALLED = (short) 0x6A88;

	// CRSService sioCRSService;

	static final byte AID_PPSE[] = { (byte) '2', (byte) 'P', (byte) 'A',
			(byte) 'Y', (byte) '.', (byte) 'S', (byte) 'Y', (byte) 'S',
			(byte) '.', (byte) 'D', (byte) 'D', (byte) 'F', (byte) '0',
			(byte) '1' };

	static final byte unionPay[] = { (byte) 0xA0, (byte) 0x00, (byte) 0x00,
			(byte) 0x03, (byte) 0x33, (byte) 0x01 };

	// 1PAY.SYS.DDF01 DF
	byte[] df = { (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59,
			(byte) 0x2e, (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2e,
			(byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31 };

	byte[] ListOfCLApplet;

	short currentLenOfList = 0;

	byte[] aids = new byte[255];

	byte[] selfFlag={(byte)0xFF,(byte)0xFF};
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {

		// GP-compliant JavaCard applet registration
		new crs_App(bArray, bOffset, bLength);
	}

	crs_App(byte[] bArray, short bOffset, byte bLength) {

		ListOfCLApplet = new byte[255];
		register(bArray, (short) (bOffset + 1), bArray[bOffset]);

	}

	public void process(APDU apdu) {

		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
            Util.arrayCopy(selfFlag, ( short ) 0, apdu.getBuffer(), ( short ) 0, ( short ) selfFlag.length);
            apdu.setOutgoingAndSend(( short ) 0, ( short ) selfFlag.length);
			return;
		}

		byte[] apduBuffer = apdu.getBuffer();
		
		apduBuffer[0] = (byte)(apduBuffer[0]&0xFC);
		
		if (apduBuffer[ISO7816.OFFSET_CLA] != (byte) 0x80) {

			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		}

		switch (apduBuffer[ISO7816.OFFSET_INS]) {

		case (byte) INS_SET_STATUS:
			processSetStatus(apdu);
			break;
		case (byte) INS_GET_STATUS:
			processGetStatus(apdu);
			break;
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	void processSetStatus(APDU apdu) {

		byte[] apduBuffer = apdu.getBuffer();
		byte P1 = apduBuffer[ISO7816.OFFSET_P1];
		byte P2 = apduBuffer[ISO7816.OFFSET_P2];

		apdu.setIncomingAndReceive();
		short off_AID = (short) (ISO7816.OFFSET_CDATA + 2);
		short len_AID = (short) (ISO7816.OFFSET_CDATA + 3);
		short sw = ISO7816.SW_NO_ERROR;


        CRSService sioCRSService = ( CRSService ) JCSystem.getAppletShareableInterfaceObject(JCSystem.lookupAID(AID_PPSE,
                                                                                                                ( short ) 0x00,
                                                                                                                ( byte ) AID_PPSE.length),
                                                                                             ( byte ) 0);
        if (sioCRSService != null)
        {
            if (P1 != CRSService.TYPE_AVAILABILITY)
            {
                ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
            }
            else
            {
                if (P1 == CRSService.TYPE_AVAILABILITY)
                {
//                    if (P2 != CRSService.TYPE_STATUS_ACTIVE)
//                    {
//                        ISOException.throwIt(ISO7816.SW_FILE_FULL);
//                    }
                    byte[] aids=new byte[6];
                    Util.arrayCopy(apduBuffer, (short)7, aids, (short)0, (short)6);
                    byte fincaFlag=Util.arrayCompare(unionPay,(short)0,aids,(short)0,(short)6);
                    short off = findAIDInList(apduBuffer, off_AID, apduBuffer[6]);
                  
                    if (off == ( short ) 0xFFFF)
                    {
                        if (P2 == CRSService.TYPE_STATUS_DEACTIVE)
                        {
                            return;
                        }
                        if (P2 == CRSService.TYPE_STATUS_ACTIVE)
                        {
                        	if (fincaFlag==0) 
                        	{
          						sw = sioCRSService.setStatusOfActivation(apduBuffer,
          								off_AID, apduBuffer[6], P2);
          						 if (sw != ISO7816.SW_NO_ERROR)
          	                    {
          	                        ISOException.throwIt(sw);
          	                    }
          					}
                            addAIDToList(apduBuffer, off_AID, (short)apduBuffer[6]);
                        }
                    }
                    else
                    {
                        	 if (P2 == CRSService.TYPE_STATUS_DEACTIVE)
                             {
                             	if(fincaFlag==0)
                             	{
                             		sw = sioCRSService.setStatusOfDeadaction(apduBuffer,
             								off_AID, apduBuffer[6], P2);
                             		 if (sw != ISO7816.SW_NO_ERROR)
                                      {
                                          ISOException.throwIt(sw);
                                      }
                             	}
                                 removeAIDFromList(off);
                             }
                        	 if (P2 == CRSService.TYPE_STATUS_ACTIVE)
                             {
                             	if (fincaFlag==0) 
                             	{
               						sw = sioCRSService.setStatusOfActivation(apduBuffer,
               								off_AID, apduBuffer[6], P2);
               						 if (sw != ISO7816.SW_NO_ERROR)
               	                    {
               	                        ISOException.throwIt(sw);
               	                    }
               					}
                             }
                    }


            }
                else
                {
                	ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
            }
        }
        else
        {
            ISOException.throwIt(SW_PPSE_IS_NOT_INSTALLED);
        }

    }

	void addAIDToList(byte[] bArray_AID, short off_AID, short len_AID) {

		JCSystem.beginTransaction();
		ListOfCLApplet[currentLenOfList++] = (byte) len_AID;
		currentLenOfList = Util.arrayCopy(bArray_AID, off_AID, ListOfCLApplet,
				currentLenOfList, len_AID);
		JCSystem.commitTransaction();
	}

	void removeAIDFromList(short off_removeAID) {
		
		byte[] tempArray=new byte[255];
		
		JCSystem.beginTransaction();
		short flagLen=ListOfCLApplet[off_removeAID];
		  Util.arrayCopy(ListOfCLApplet, (short)0, tempArray, (short)0, off_removeAID);
		  Util.arrayCopy(ListOfCLApplet,
				  (short)(off_removeAID + 1 + ListOfCLApplet[off_removeAID]),
	                         tempArray,
	                         off_removeAID,
	                         ((short)(currentLenOfList - off_removeAID -1 -ListOfCLApplet[off_removeAID] )));
		  Util.arrayCopy(tempArray, (short)0, ListOfCLApplet, (short)0, (short)(currentLenOfList  -1 -flagLen));
		  currentLenOfList= (short)(currentLenOfList  -1 -flagLen);
		JCSystem.commitTransaction();
	}

	public short findAIDInList(byte[] bArray_AID, short off_AID, short len_AID) {

		short off = 0;
		boolean isFound = false;
		short len = 0;
		while (off < currentLenOfList) {
			len = (short) (ListOfCLApplet[off++] & 0xFF);
			if (len == len_AID) {
				if (Util.arrayCompare(ListOfCLApplet, off, bArray_AID, off_AID,
						len_AID) == 0) {
					isFound = true;
					break;
				}
			}
			off = (short) (off + len);

		}
		if (isFound) {
			return (short) (off - 1);
		} else {
			return (short) 0xFFFF;
		}
	}

	void processGetStatus(APDU apdu) {

		byte[] apduBuffer = apdu.getBuffer();
		if (apduBuffer[4]>0) {
			apdu.setIncomingAndReceive();
		}
		byte P1 = apduBuffer[ISO7816.OFFSET_P1];
		if (P1 != TYPE_GET_STATUS_APPLICATION) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		} else {
			Util.arrayCopyNonAtomic(ListOfCLApplet, (short) 0, apduBuffer,
					(short) 0, currentLenOfList);
			apdu.setOutgoingAndSend((short) 0, currentLenOfList);
		}
	}

	public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {

		return this;
	}

	public short setStatusOfActivation(byte[] bArray_AID, short off_AID,
			short len_AID, byte bStatus) {
		return 0;
	}

	public short setStatusOfDeadaction(byte[] bArray_AID, short off_AID,
			short len_AID, byte bStatus) {
		return 0;
	}
}