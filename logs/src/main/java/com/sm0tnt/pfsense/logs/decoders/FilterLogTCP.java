package com.sm0tnt.pfsense.logs.decoders;

import java.util.ArrayList;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class FilterLogTCP extends FilterLog {
	public static final String SOURCE_PORT = "srcport";
	public static final String DESTINATION_PORT = "dstport";
	public static final String DATA_LENGTH = "datalength";
	public static final String TCP_FLAGS = "tcpflags";
	public static final String SEQUENCE_NUMBER = "sequencenumber";
	public static final String TCP_ACK = "tcpack";
	public static final String WINDOW = "window";
	public static final String URG = "urg";
	public static final String TCP_OPTIONS = "tcpoptions";

	private int srcPort;
	private int dstPort;
	private int dataLength;
	private String tcpFlags;
	private int sequenceNumber;
	private int tcpAck;
	private int window;
	private int urg;
	private ArrayList<String> tcpOptions = new ArrayList<>();

	/**
	 * Constructor.
	 * 
	 * @param srcPort        The source port.
	 * @param dstPort        The destination port.
	 * @param dataLength     The data length.
	 * @param tcpFlags       The TCP flags.
	 * @param sequenceNumber The sequence number.
	 * @param tcpAck         The TCP ack.
	 * @param window         The window.
	 * @param urg            The urg.
	 * @param tcpOptions     The tcp option.
	 */
	public FilterLogTCP(int srcPort, int dstPort, int dataLength, String tcpFlags, int sequenceNumber, int tcpAck, int window, int urg, ArrayList<String> tcpOptions) {
		this.srcPort = srcPort;
		this.dstPort = dstPort;
		this.dataLength = dataLength;
		this.tcpFlags = StringUtils.isBlank(tcpFlags) ? tcpFlags : tcpFlags.toLowerCase();
		this.sequenceNumber = sequenceNumber;
		this.tcpAck = tcpAck;
		this.window = window;
		this.urg = urg;
		if (tcpOptions != null) {
			ArrayList<String> tmp = new ArrayList<>();
			for (String s : tcpOptions)
				if (StringUtils.isNotBlank(s))
					tmp.add(s.toLowerCase());
			this.tcpOptions = tmp;
		}
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
	 * @return the tcpFlags
	 */
	public String getTcpFlags() {
		return tcpFlags;
	}

	/**
	 * @return the sequenceNumber
	 */
	public int getSequenceNumber() {
		return sequenceNumber;
	}

	/**
	 * @return the tcpAck
	 */
	public int getTcpAck() {
		return tcpAck;
	}

	/**
	 * @return the window
	 */
	public int getWindow() {
		return window;
	}

	/**
	 * @return the urg
	 */
	public int getUrg() {
		return urg;
	}

	/**
	 * @return the tcpOptions
	 */
	public ArrayList<String> getTcpOptions() {
		return tcpOptions;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ObjectNode toObjectNode(ObjectNode n) {
		ObjectMapper mapper = new ObjectMapper();
		if (n == null)
			n = mapper.createObjectNode();

		ArrayNode topt = mapper.createArrayNode();

		if (this.tcpOptions != null && tcpOptions.size() > 0)
			for (String o : this.tcpOptions)
				topt.add(o);

		n.put(SOURCE_PORT, this.srcPort);
		n.put(DESTINATION_PORT, this.dstPort);
		n.put(DATA_LENGTH, this.dataLength);

		if (StringUtils.isNotBlank(this.tcpFlags))
			n.put(TCP_FLAGS, this.tcpFlags);

		if (this.sequenceNumber > -1)
			n.put(SEQUENCE_NUMBER, this.sequenceNumber);

		if (this.tcpAck > -1)
			n.put(TCP_ACK, this.tcpAck);

		if (this.window > -1)
			n.put(WINDOW, this.window);

		if (this.urg > -1)
			n.put(URG, this.urg);

		if (topt.size() > 0)
			n.set(TCP_OPTIONS, topt);

		return n;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		if (this.tcpOptions != null && this.tcpOptions.size() > 0) {
			StringBuffer tmp = new StringBuffer();
			for (String s : this.tcpOptions) {
				if (tmp.length() > 0)
					tmp.append("; ");
				tmp.append(s);
			}
			sb.append("; ").append(TCP_OPTIONS).append("=[").append(tmp).append("]");
		}

		return new StringBuffer()
				.append(getClass().getSimpleName())
				.append("(")
				.append(SOURCE_PORT).append("=").append(this.srcPort)
				.append("; ").append(DESTINATION_PORT).append("=").append(this.dstPort)
				.append("; ").append(DATA_LENGTH).append("=").append(this.dataLength)
				.append("; ").append(TCP_FLAGS).append("=").append(this.tcpFlags)
				.append("; ").append(SEQUENCE_NUMBER).append("=").append(this.sequenceNumber)
				.append("; ").append(TCP_ACK).append("=").append(this.tcpAck)
				.append("; ").append(WINDOW).append("=").append(this.window)
				.append("; ").append(URG).append("=").append(this.urg)
				.append(sb)
				.append(")")
				.toString();
	}
}
