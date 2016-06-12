package com.cfcc.crs;

import javacard.framework.ISO7816;
import javacard.framework.Shareable;

public interface CRSService extends Shareable{
	static final byte TYPE_AVAILABILITY   		  	= (byte)0x01;
	static final byte TYPE_PRIORITY_ORDER			=  (byte)0x02;
	
	static final byte TYPE_STATUS_ACTIVE =(byte)0x01;
	static final byte TYPE_STATUS_DEACTIVE =(byte)0x00;
	
	static final byte PROIORITY_HIGHEST = (byte)0x01;
	static final byte PROIORITY_LOWEST = (byte)0x81;
	
	static final short SW_APPLICAITION_NOT_FOUND = (short)ISO7816.SW_FILE_NOT_FOUND;
	static final short SW_ACTION_SUCCESSFULL = (short)0x9000;
	static final short SW_ACTION_FAIL = (short)0x9000;
	
	static final short SW_MORE_DATA_AVAILABLE = (short) 0x6300;
	//static final short SW_OPERATION_FAIL = (short) 0x6320;
	static final short SW_OPERATION_FAIL_FOR_CONFLICT = (short) 0x6330;
	
	
	 public short findAIDInList(byte[] bArray_AID, short off_AID, short len_AID);
	 

		/**
		 * 
		 * @param bArray_AID
		 * @param off_AID
		 * @param len_AID
		 * @param bStatus
		 * @return
		 */
		public short setStatusOfActivation(byte[] bArray_AID,short off_AID,short len_AID,byte bStatus);
		
		
		public short setStatusOfDeadaction(byte[] bArray_AID,short off_AID,short len_AID,byte bStatus);
}
