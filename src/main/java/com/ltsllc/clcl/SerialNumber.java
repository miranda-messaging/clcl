package com.ltsllc.clcl;

import java.math.BigInteger;
import java.nio.ByteBuffer;

/**
 * A serial number, suitable for use with a certificate.
 *
 * <p>
 *     The class uses {@link System#currentTimeMillis()} to come up with a value for the serial number.
 * </p>
 */
public class SerialNumber {
    private long longValue;

    public SerialNumber () {
        setLongValue(System.currentTimeMillis());
    }

    public long getLongValue() {
        return longValue;
    }

    public void setLongValue(long longValue) {
        this.longValue = longValue;
    }

    public BigInteger toBigInteger () {
        ByteBuffer byteBuffer = ByteBuffer.allocate(Long.BYTES);
        byteBuffer.putLong(getLongValue());
        byte[] bytes = byteBuffer.array();
        return new BigInteger(bytes);
    }
}
