package io.flutter.plugins.nfc_emulator;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.os.Vibrator;
import android.util.Log;
import android.widget.Toast;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class NfcEmulatorService extends HostApduService {

    private static final String TAG = "CardService";
    // AID for our loyalty card service.
    private static final String SAMPLE_LOYALTY_CARD_AID = "666B65630001";

    // Format: [Class | Instruction | Parameter 1 | Parameter 2]
    private static final String SELECT_APDU_HEADER = "00A40400";
    // Format: [Class | Instruction | Parameter 1 | Parameter 2]
    private static final String GET_DATA_APDU_HEADER = "00CA0000";
    // "OK" status word sent in response to SELECT AID command (0x9000)
    private static final byte[] SELECT_OK_SW = HexStringToByteArray("9000");
    // "UNKNOWN" status word sent in response to invalid APDU command (0x0000)
    private static final byte[] UNKNOWN_CMD_SW = HexStringToByteArray("0000");
    private static final byte[] SELECT_APDU = BuildSelectApdu(SAMPLE_LOYALTY_CARD_AID);
    private static final byte[] GET_DATA_APDU = BuildGetDataApdu();


    private String m_sCardNumber;
    private String m_sKey;
    public SharedPreferences mSharePerf;
    public SharedPreferences.Editor mEditor;
    private String sAESCardNumToSend;

    public Vibrator mVibrator;



    @Override
    public void onCreate() {
        super.onCreate();

        mSharePerf = getSharedPreferences("NfcEmulator", Context.MODE_PRIVATE);
        mEditor = mSharePerf.edit();
        m_sCardNumber =  mSharePerf.getString("cardUid",null);

        m_sKey = mSharePerf.getString("aesKey",null);
        Log.d(TAG,"CARD UID :"+m_sCardNumber);
        Log.d(TAG,"CARD KEY :"+m_sKey);

        mVibrator = (Vibrator)this.getSystemService(this.VIBRATOR_SERVICE);


    }

    @Override
    public byte[] processCommandApdu(byte[] bytes, Bundle bundle) {

        byte[] commandApdu;
        commandApdu = bytes;

        //StartNFCEmulate flag
        boolean bStarNFC = mSharePerf.getString("cardUid",null)!=null;
        if(!bStarNFC) {
            Log.d(TAG,"STOPPED SERVICE");
            return UNKNOWN_CMD_SW; //don't start emulator
        }

        Log.i(TAG,"PROCESS");


        // If the APDU matches the SELECT AID command for this service,
        // send the loyalty card account number, followed by a SELECT_OK status trailer (0x9000).

        if (Arrays.equals(SELECT_APDU, commandApdu)) {

            String account = "";
            Log.i(TAG,"send data1:"+account);
            byte[] accountBytes = HexStringToByteArray(account);

            return ConcatArrays(accountBytes, SELECT_OK_SW);

        } else {

            byte[] DeAESRecByte = new byte[0];
            try {

                DeAESRecByte = AESUtils.decrypt(m_sKey,commandApdu);

            } catch (Exception e) {
                e.printStackTrace();
            }

            if (Arrays.equals(GET_DATA_APDU, DeAESRecByte)) {

                try {
                    byte[] bytesCardNum = MakeAesCardNumToSend();
                    Log.d(TAG, "NFC Emulator" + new String(bytesCardNum));

                    mVibrator.vibrate(400);
                    return bytesCardNum;
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

        }


        return UNKNOWN_CMD_SW;
    }

    @Override
    public void onDeactivated(int i) {

    }


    /**
     * Build APDU for SELECT AID command. This command indicates which service a reader is
     * interested in communicating with. See ISO 7816-4.
     *
     * @param aid Application ID (AID) to select
     * @return APDU for SELECT AID command
     */
    public static byte[] BuildSelectApdu(String aid) {
        // Format: [CLASS | INSTRUCTION | PARAMETER 1 | PARAMETER 2 | LENGTH | DATA]
        return HexStringToByteArray(SELECT_APDU_HEADER + String.format("%02X",
                aid.length() / 2) + aid);
    }

    /**
     * Build APDU for GET_DATA command. See ISO 7816-4.
     *
     * @return APDU for SELECT AID command
     */
    public static byte[] BuildGetDataApdu() {
        // Format: [CLASS | INSTRUCTION | PARAMETER 1 | PARAMETER 2 | LENGTH | DATA]
        return HexStringToByteArray(GET_DATA_APDU_HEADER + "0FFF");
    }

    private byte[] MakeAesCardNumToSend() throws Exception {


        if(0 == m_sCardNumber.length() || 16 != m_sKey.length()) {

            return null;
        }
        String sCardMsg =  String.format("%02X", m_sCardNumber.length() / 2) + m_sCardNumber;

        // Toast.makeText(CardService.this, sCardMsg, Toast.LENGTH_LONG).show();
        byte[] accountBytes = HexStringToByteArray(sCardMsg);

        byte[] ByteToSend = ConcatArrays(accountBytes, SELECT_OK_SW);

        //  return ByteToSend;

        byte[] AESByteToSend = AESUtils.encrypt(m_sKey,ByteToSend);

        return AESByteToSend;
    }

    /**
     * Utility method to convert a byte array to a hexadecimal string.
     *
     * @param bytes Bytes to convert
     * @return String, containing hexadecimal representation.
     */
    public static String ByteArrayToHexString(byte[] bytes) {
        final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        char[] hexChars = new char[bytes.length * 2]; // Each byte has two hex characters (nibbles)
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF; // Cast bytes[j] to int, treating as unsigned value
            hexChars[j * 2] = hexArray[v >>> 4]; // Select hex character from upper nibble
            hexChars[j * 2 + 1] = hexArray[v & 0x0F]; // Select hex character from lower nibble
        }
        return new String(hexChars);
    }


    /**
     * Utility method to convert a hexadecimal string to a byte string.
     *
     * <p>Behavior with input strings containing non-hexadecimal characters is undefined.
     *
     * @param s String containing hexadecimal characters to convert
     * @return Byte array generated from input
     * @throws java.lang.IllegalArgumentException if input length is incorrect
     */
    public static byte[] HexStringToByteArray(String s) throws IllegalArgumentException {
        int len = s.length();
        if (len % 2 == 1) {
            throw new IllegalArgumentException("Hex string must have even number of characters");
        }
        byte[] data = new byte[len / 2]; // Allocate 1 byte per 2 hex characters
        for (int i = 0; i < len; i += 2) {
            // Convert each character into a integer (base-16), then bit-shift into place
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * Utility method to concatenate two byte arrays.
     * @param first First array
     * @param rest Any remaining arrays
     * @return Concatenated copy of input arrays
     */
    public static byte[] ConcatArrays(byte[] first, byte[]... rest) {
        int totalLength = first.length;
        for (byte[] array : rest) {
            totalLength += array.length;
        }
        byte[] result = Arrays.copyOf(first, totalLength);
        int offset = first.length;
        for (byte[] array : rest) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }

        //  Log.i(TAG, "ConcatArrays: "+ ByteArrayToHexString(result));
        return result;
    }


}
