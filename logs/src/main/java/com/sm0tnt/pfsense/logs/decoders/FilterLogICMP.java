package com.sm0tnt.pfsense.logs.decoders;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sm0tnt.addr.iptools.IPAddress;

public class FilterLogICMP extends FilterLog {
	public static final String REQUEST = "request";
	public static final String REPLY = "reply";
	public static final String UNREACH = "unreach";
	public static final String UNREACH_PORT = "unreachport";
	public static final String TSTAMP = "tstamp";
	public static final String TIME_XCEED = "timexceed";
	public static final String REDIRECT = "redirect";
	public static final String UNKNOWN = "unknown";

	public static final String ICMP_TYPE = "icmptype";
	public static final String ID = "id";
	public static final String SEQUENCE = "sequence";
	public static final String ADDRESS = "ip_address";
	public static final String PROTOCOL = "protocol";
	public static final String PORT_NUMBER = "portNumber";
	public static final String LENGTH = "length";
	public static final String REASON = "reason";
	private static final String ADDRESS_TYPE = "addresstype";
	private static final String TO_ADDRESS = "ip_toaddress";

	public enum ICMPType {
		Request,
		Reply,
		Unreach,
		UnreachPort,
		TStamp,
		TimeXceed,
		Redirect,
		Unknown;

		public static ICMPType getType(String s) {
			if (StringUtils.isBlank(s))
				return Unknown;

			s = s.toLowerCase();

			switch (s) {
				case REQUEST:
					return Request;

				case REPLY:
					return Reply;

				case UNREACH:
					return Unreach;

				case UNREACH_PORT:
					return UnreachPort;

				case TSTAMP:
					return TStamp;

				case TIME_XCEED:
					return TimeXceed;

				case REDIRECT:
					return Redirect;

				default:
					return Unknown;
			}
		}

		public String toString() {
			switch (this) {
				case Request:
					return REQUEST;

				case Reply:
					return REPLY;

				case TStamp:
					return TSTAMP;

				case Unknown:
					return UNKNOWN;

				case Unreach:
					return UNREACH;

				case UnreachPort:
					return UNREACH_PORT;

				case TimeXceed:
					return TIME_XCEED;

				case Redirect:
					return REDIRECT;

				default:
					return UNKNOWN;
			}
		}
	}

	private ICMPType icmpType;
	private int id = -1;
	private int sequence = -1;
	private IPAddress address;
	private IPAddress toAddress;
	private String protocol;
	private int portNumber = -1;
	private int length = -1;
	private String reason;
	private String addressType;
	private String unknownType;

	/**
	 * Constructor.
	 * 
	 * @param icmpType The type of ICMP message.
	 * @param id       The id.
	 * @param sequence The sequence.
	 * @param length   The length.
	 */
	public FilterLogICMP(ICMPType icmpType, int id, int sequence, int length) {
		this.icmpType = icmpType;
		this.id = id;
		this.sequence = sequence;
		this.length = length;
	}

	/**
	 * Constructor.
	 * 
	 * @param icmpType   The type of ICMP message.
	 * @param address    The address.
	 * @param protocol   The protocol.
	 * @param portNumber The port number.
	 * @param length     The length.
	 */
	public FilterLogICMP(ICMPType icmpType, IPAddress address, String protocol, int portNumber, int length) {
		this.icmpType = icmpType;
		this.address = address;
		this.protocol = protocol;
		this.portNumber = portNumber;
		this.length = length;
	}

	/**
	 * Constructor.
	 * 
	 * @param icmpType    The type of ICMP message.
	 * @param addressType The type of address.
	 * @param address     The address.
	 * @param reason      The reason for the unreachable message.
	 * @param length      The length.
	 */
	public FilterLogICMP(ICMPType icmpType, String addressType, IPAddress address, String reason, int length) {
		this.icmpType = icmpType;
		this.addressType = addressType;
		this.address = address;
		this.reason = reason;
		this.length = length;
	}

	/**
	 * Constructor.
	 * 
	 * @param icmpType        The type of ICMP message.
	 * @param unknwonICMPType The unknown type of ICMP message.
	 * @param length          The length.
	 */
	public FilterLogICMP(ICMPType icmpType, String unknwonICMPType, int length) {
		this.icmpType = icmpType;
		this.unknownType = unknwonICMPType;
		this.length = length;
	}

	/**
	 * @param icmpType  The type of ICP message.
	 * @param address   The address.
	 * @param toAddress The to address.
	 */
	public FilterLogICMP(ICMPType icmpType, IPAddress address, IPAddress toAddress) {
		this.icmpType = icmpType;
		this.address = address;
		this.toAddress = toAddress;
	}

	/**
	 * @return true if unknown ICMP type.
	 */
	public boolean isUnknown() {
		return this.icmpType == null || this.icmpType == ICMPType.Unknown;
	}

	/**
	 * @return true if unreach ICMP type.
	 */
	public boolean isUnreach() {
		return this.icmpType != null && this.icmpType == ICMPType.Unreach;
	}

	/**
	 * @return true if unreach port ICMP type.
	 */
	public boolean isUnreachPort() {
		return this.icmpType != null && this.icmpType == ICMPType.UnreachPort;
	}

	/**
	 * @return true if request ICMP type.
	 */
	public boolean isRequest() {
		return this.icmpType != null && this.icmpType == ICMPType.Request;
	}

	/**
	 * @return true if reply ICMP type.
	 */
	public boolean isReply() {
		return this.icmpType != null && this.icmpType == ICMPType.Reply;
	}

	/**
	 * @return true if tstamp ICMP type.
	 */
	public boolean isTStamp() {
		return this.icmpType != null && this.icmpType == ICMPType.TStamp;
	}

	/**
	 * @return the icmpType
	 */
	public ICMPType getIcmpType() {
		return icmpType;
	}

	/**
	 * @return the id
	 */
	public int getId() {
		return id;
	}

	/**
	 * @return the sequence
	 */
	public int getSequence() {
		return sequence;
	}

	/**
	 * @return the address
	 */
	public IPAddress getAddress() {
		return address;
	}

	/**
	 * @return the protocol
	 */
	public String getProtocol() {
		return protocol;
	}

	/**
	 * @return the portNumber
	 */
	public int getPortNumber() {
		return portNumber;
	}

	/**
	 * @return the length
	 */
	public int getLength() {
		return length;
	}

	/**
	 * @return the reason
	 */
	public String getReason() {
		return reason;
	}

	/**
	 * @return the addressType
	 */
	public String getAddressType() {
		return addressType;
	}

	/**
	 * @return the to address.
	 */
	public IPAddress getToAddress() {
		return this.toAddress;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ObjectNode toObjectNode(ObjectNode n) {
		if (n == null)
			n = new ObjectMapper().createObjectNode();

		if (this.icmpType != null)
			n.put(ICMP_TYPE, this.icmpType.toString());

		if (StringUtils.isNotBlank(this.unknownType))
			n.put(UNKNOWN, this.unknownType);

		if (this.id > -1)
			n.put(ID, this.id);

		if (this.sequence > -1)
			n.put(SEQUENCE, this.sequence);

		if (this.address != null)
			n.put(ADDRESS, this.address.toString());

		if (this.toAddress != null)
			n.put(TO_ADDRESS, this.toAddress.toString());

		if (StringUtils.isNotBlank(this.protocol))
			n.put(PROTOCOL, this.protocol);

		if (this.portNumber > -1)
			n.put(PORT_NUMBER, this.portNumber);

		if (this.length > 0)
			n.put(LENGTH, this.length);

		if (StringUtils.isNotBlank(this.reason))
			n.put(REASON, this.reason);

		if (StringUtils.isNotBlank(this.addressType))
			n.put(ADDRESS_TYPE, this.addressType);

		return n;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		StringBuffer result = new StringBuffer()
				.append(getClass().getSimpleName())
				.append("(");

		StringBuffer sb = new StringBuffer();

		addToStringBuffer(this.icmpType != null, sb, ICMP_TYPE, this.icmpType);
		addToStringBuffer(StringUtils.isNotBlank(this.unknownType), sb, UNKNOWN, this.unknownType);
		addToStringBuffer(this.id > -1, sb, ID, this.id);
		addToStringBuffer(this.sequence > -1, sb, SEQUENCE, this.sequence);
		addToStringBuffer(this.address != null, sb, ADDRESS, this.address);
		addToStringBuffer(this.toAddress != null, sb, TO_ADDRESS, this.toAddress);
		addToStringBuffer(StringUtils.isNotBlank(this.protocol), sb, PROTOCOL, this.protocol);
		addToStringBuffer(this.portNumber > -1, sb, PORT_NUMBER, this.portNumber);
		addToStringBuffer(this.length > 0, sb, LENGTH, this.length);
		addToStringBuffer(StringUtils.isNotBlank(this.reason), sb, REASON, this.reason);
		addToStringBuffer(StringUtils.isNotBlank(this.addressType), sb, ADDRESS_TYPE, this.addressType);

		return result.append(sb).append(")").toString();
	}
}
