package com.sm0tnt.pfsense.logs.decoders;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sm0tnt.addr.iptools.IPAddress;
import com.sm0tnt.addr.iptools.IPv4Address;

public class FilterLogIPv4 extends FilterLog {
	public static final String SRC_ADDR = "ip_srcaddr";
	public static final String DEST_ADDR = "ip_destaddr";
	public static final String TOS = "tos";
	public static final String ECN = "ecn";
	public static final String TTL = "ttl";
	public static final String ID = "id";
	public static final String OFFSET = "offset";
	public static final String FLAGS = "flags";
	public static final String PROTOCOL_ID = "protocolid";
	public static final String PROTOCOL_TEXT = "protocoltext";
	public static final String DATA_LENGTH = "datalength";

	private IPv4Address srcAddr;
	private IPv4Address destAddr;
	private int tos;
	private String ecn;
	private int ttl;
	private int id;
	private int offset;
	private String flags;
	private int protocolId;
	private String protocolText;
	private int dataLength;

	public FilterLogIPv4(IPAddress srcAddr, IPAddress destAddr, int tos, String ecn, int ttl, int id, int offset, String flags, int protocolId, String protocolText, int dataLength) {
		this.srcAddr = (IPv4Address) srcAddr;
		this.destAddr = (IPv4Address) destAddr;
		this.tos = tos;
		this.ecn = ecn;
		this.ttl = ttl;
		this.id = id;
		this.offset = offset;
		this.flags = flags;
		this.protocolId = protocolId;
		this.protocolText = protocolText;
		this.dataLength = dataLength;
	}

	/**
	 * @return the srcAddr
	 */
	public IPv4Address getSrcAddr() {
		return srcAddr;
	}

	/**
	 * @return the destAddr
	 */
	public IPv4Address getDestAddr() {
		return destAddr;
	}

	/**
	 * @return the tos
	 */
	public int getTOS() {
		return tos;
	}

	/**
	 * @return the ecn
	 */
	public String getECN() {
		return ecn;
	}

	/**
	 * @return the ttl
	 */
	public int getTTL() {
		return ttl;
	}

	/**
	 * @return the id
	 */
	public int getId() {
		return id;
	}

	/**
	 * @return the offset
	 */
	public int getOffset() {
		return offset;
	}

	/**
	 * @return the flags
	 */
	public String getFlags() {
		return flags;
	}

	/**
	 * @return the protocolId
	 */
	public int getProtocolId() {
		return protocolId;
	}

	/**
	 * @return the protocolText
	 */
	public String getProtocolText() {
		return protocolText;
	}

	/**
	 * @return the dataLength.
	 */
	public int getDataLength() {
		return this.dataLength;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ObjectNode toObjectNode(ObjectNode n) {
		if (n == null)
			n = new ObjectMapper().createObjectNode();

		n.put(SRC_ADDR, this.srcAddr.toString());
		n.put(DEST_ADDR, this.destAddr.toString());
		n.put(TOS, this.tos);
		n.put(ECN, StringUtils.isNotBlank(this.ecn) ? this.ecn : null);
		n.put(TTL, this.ttl);
		n.put(ID, this.id);
		n.put(OFFSET, this.offset);
		n.put(FLAGS, this.flags);
		n.put(PROTOCOL_ID, this.protocolId);
		n.put(PROTOCOL_TEXT, this.protocolText);
		n.put(DATA_LENGTH, this.dataLength);

		return n;
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
				.append("; ").append(TOS).append("=").append(this.tos)
				.append("; ").append(ECN).append("=").append(this.ecn)
				.append("; ").append(TTL).append("=").append(this.ttl)
				.append("; ").append(ID).append("=").append(this.id)
				.append("; ").append(OFFSET).append("=").append(this.offset)
				.append("; ").append(FLAGS).append("=").append(this.flags)
				.append("; ").append(PROTOCOL_ID).append("=").append(this.protocolId)
				.append("; ").append(PROTOCOL_TEXT).append("=").append(this.protocolText)
				.append("; ").append(DATA_LENGTH).append("=").append(this.dataLength)
				.append(")")
				.toString();
	}
}
