package com.sm0tnt.pfsense.logs.decoders;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public abstract class UnboundMessage implements RSysLogPayload {
	public static final String CLIENT_IP = "client_ip";
	public static final String Q_NAME = "q_name";
	public static final String TYPE = "type";
	public static final String CLASS = "class";
	public static final String R_CODE = "rcode";
	public static final String DURATION_USEC = "duration_usec";
	public static final String DURATION = "duration";
	public static final String CACHED = "cached";
	public static final String PKT_LEN = "pktlen";

	/**
	 * @return a new ObjectNode.
	 */
	protected ObjectNode getObjectNode() {
		return new ObjectMapper().createObjectNode();
	}
}
