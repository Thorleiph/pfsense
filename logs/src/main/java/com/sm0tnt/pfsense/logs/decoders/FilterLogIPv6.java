package com.sm0tnt.pfsense.logs.decoders;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sm0tnt.addr.iptools.IPAddress;
import com.sm0tnt.addr.iptools.IPv6Address;

public class FilterLogIPv6 extends FilterLog {
	public static final String SRC_ADDR = FilterLogIPv4.SRC_ADDR;
	public static final String DEST_ADDR = FilterLogIPv4.DEST_ADDR;
	public static final String CLASS = "class";
	public static final String FLOW_LABEL = "flowlabel";
	public static final String HOP_LIMIT = "hoplimit";
	public static final String DATA_LENGTH = "datalength";

	private IPv6Address srcAddr;
	private IPv6Address destAddr;
	private int v6Class;
	private int flowLabel;
	private int hopLimit;
	private int protocolId;
	private String protocolText;
	private int dataLength;

	/**
	 * Constructor.
	 * 
	 * @param srcAddr      The source address.
	 * @param destAddr     The destination address.
	 * @param v6Class      The class.
	 * @param flowLabel    The flow label.
	 * @param hopLimit     The hop limit.
	 * @param protoclId    The protocol id.
	 * @param protocolText The protocol text.
	 * @param dataLength   The data length.
	 */
	public FilterLogIPv6(IPAddress srcAddr, IPAddress destAddr, int v6Class, int flowLabel, int hopLimit, int protoclId, String protocolText, int dataLength) {
		this.srcAddr = (IPv6Address) srcAddr;
		this.destAddr = (IPv6Address) destAddr;
		this.v6Class = v6Class;
		this.flowLabel = flowLabel;
		this.hopLimit = hopLimit;
		this.protocolId = protoclId;
		this.protocolText = protocolText;
		this.dataLength = dataLength;
	}

	/**
	 * @return the srcAddr
	 */
	public IPv6Address getSrcAddr() {
		return srcAddr;
	}

	/**
	 * @return the destAddr
	 */
	public IPv6Address getDestAddr() {
		return destAddr;
	}

	/**
	 * @return the v6Class
	 */
	public int getV6Class() {
		return v6Class;
	}

	/**
	 * @return the flowLabel
	 */
	public int getFlowLabel() {
		return flowLabel;
	}

	/**
	 * @return the hopLimit
	 */
	public int getHopLimit() {
		return hopLimit;
	}

	/**
	 * @return the protocol id.
	 */
	public int getProtocolId() {
		return this.protocolId;
	}

	/**
	 * @return the protocol text.
	 */
	public String getProtocolText() {
		return this.protocolText;
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

		return n.put(SRC_ADDR, this.srcAddr.toString())
				.put(DEST_ADDR, this.destAddr.toString())
				.put(CLASS, this.v6Class)
				.put(FLOW_LABEL, this.flowLabel)
				.put(HOP_LIMIT, this.hopLimit)
				.put(DATA_LENGTH, this.dataLength);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return new StringBuffer()
				.append(getClass().getSimpleName()).append("(")
				.append(SRC_ADDR).append("=").append(this.srcAddr)
				.append("; ").append(DEST_ADDR).append("=").append(this.destAddr)
				.append("; ").append(CLASS).append("=").append(this.v6Class)
				.append("; ").append(FLOW_LABEL).append("=").append(this.flowLabel)
				.append("; ").append(HOP_LIMIT).append("=").append(this.hopLimit)
				.append("; ").append(DATA_LENGTH).append("=").append(this.dataLength)
				.append(")")
				.toString();
	}
}
