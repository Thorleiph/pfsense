package com.sm0tnt.pfsense.logs.decoders;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class FilterLogUDP extends FilterLog {
	public static final String SOURCE_PORT = "srcport";
	public static final String DESTINATION_PORT = "dstport";
	public static final String DATA_LENGTH = "datalength";

	private int srcPort;
	private int dstPort;
	private int dataLength;

	/**
	 * Constructor.
	 * 
	 * @param srcPort    The source port.
	 * @param dstPort    The destination port.
	 * @param dataLength The data length.
	 */
	public FilterLogUDP(int srcPort, int dstPort, int dataLength) {
		this.srcPort = srcPort;
		this.dstPort = dstPort;
		this.dataLength = dataLength;
	}

	/**
	 * @return the srcPort
	 */
	public int getSrcPort() {
		return srcPort;
	}

	/**
	 * @return the dstPort
	 */
	public int getDstPort() {
		return dstPort;
	}

	/**
	 * @return the dataLength
	 */
	public int getDataLength() {
		return dataLength;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ObjectNode toObjectNode(ObjectNode n) {
		if (n == null)
			n = new ObjectMapper().createObjectNode();

		return n.put(SOURCE_PORT, this.srcPort)
				.put(DESTINATION_PORT, this.dstPort)
				.put(DATA_LENGTH, this.dataLength);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return new StringBuffer()
				.append(getClass().getSimpleName())
				.append("(")
				.append(SOURCE_PORT).append("=").append(this.srcPort)
				.append("; ").append(DESTINATION_PORT).append("=").append(this.dstPort)
				.append("; ").append(DATA_LENGTH).append("=").append(this.dataLength)
				.append(")")
				.toString();
	}
}
