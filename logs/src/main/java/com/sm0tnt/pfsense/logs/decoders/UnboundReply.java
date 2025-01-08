package com.sm0tnt.pfsense.logs.decoders;

import java.util.ArrayList;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sm0tnt.addr.iptools.IPAddress;

public class UnboundReply extends UnboundMessage {
	public static final String IN_ADDR_ARPA_ENDING = ".in-addr.arpa.";
	public static final String IN_ADDR_ARPA = "in-addr-arpa";

	private IPAddress clientIp;
	private String qname;
	private String type;
	private String clazz;
	private String rcode;
	private Double dur_tv_sec_usec;
	private long duration;
	private boolean cached;
	private int pktlen;

	private boolean inAddrArpa = false;

	private ArrayList<String> parts;

	/**
	 * Constructor.
	 * 
	 * @param clientIp        The client ip.
	 * @param qname           The qname.
	 * @param type            The type.
	 * @param clazz           The class.
	 * @param rcode           The rcode.
	 * @param dur_tv_sec_usec The duration.
	 * @param cached          The cached.
	 * @param pktlen          The packet length.
	 */
	public UnboundReply(IPAddress clientIp, String qname, String type, String clazz, String rcode, Double dur_tv_sec_usec, boolean cached, int pktlen) {
		this.clientIp = clientIp;
		this.qname = qname;
		this.type = type;
		this.clazz = clazz;
		this.rcode = rcode;
		this.dur_tv_sec_usec = dur_tv_sec_usec;
		this.duration = (long) (this.dur_tv_sec_usec * 1000);
		this.cached = cached;
		this.pktlen = pktlen;

		this.inAddrArpa = qname.endsWith(IN_ADDR_ARPA_ENDING);

		if (this.qname.endsWith("."))
			this.qname = this.qname.substring(0, this.qname.lastIndexOf('.'));
	}

	/**
	 * @return a list with the domain parts starting with the root domain.
	 */
	public ArrayList<String> getDomainNameParts() {
		if (this.parts == null) {
			this.parts = new ArrayList<>();
			String[] p = this.qname.split("\\.");

			for (int i = p.length - 1; i > -1; --i)
				this.parts.add(p[i]);
		}

		return this.parts;
	}

	/**
	 * @return true if qname ends with .in-addr.arpa.
	 */
	public boolean isInAddrArpa() {
		return this.inAddrArpa;
	}

	/**
	 * @return the clientIp
	 */
	public IPAddress getClientIp() {
		return clientIp;
	}

	/**
	 * @return the qname
	 */
	public String getQname() {
		return qname;
	}

	/**
	 * @return the type
	 */
	public String getType() {
		return type;
	}

	/**
	 * @return the clazz
	 */
	public String getClazz() {
		return clazz;
	}

	/**
	 * @return the rcode
	 */
	public String getRcode() {
		return rcode;
	}

	/**
	 * @return the dur_tv_sec_usec
	 */
	public Double getDur_tv_sec_usec() {
		return dur_tv_sec_usec;
	}

	/**
	 * @return the duration.
	 */
	public long getDuration() {
		return duration;
	}

	/**
	 * @return the cached
	 */
	public boolean isCached() {
		return cached;
	}

	/**
	 * @return the pktlen
	 */
	public int getPktlen() {
		return pktlen;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ObjectNode toObjectNode(ObjectNode n) {
		if (n == null)
			n = getObjectNode();

		return n
				.put(CLIENT_IP, this.clientIp.toString())
				.put(Q_NAME, this.qname)
				.put(TYPE, this.type)
				.put(CLASS, this.clazz)
				.put(R_CODE, this.rcode)
				.put(DURATION_USEC, this.dur_tv_sec_usec)
				.put(DURATION, this.duration)
				.put(CACHED, this.cached)
				.put(PKT_LEN, this.pktlen);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return new StringBuffer()
				.append(getClass().getSimpleName()).append("(")
				.append(CLIENT_IP).append("=").append(clientIp.toString()).append("; ")
				.append(Q_NAME).append("=").append(this.qname).append("; ")
				.append(TYPE).append("=").append(this.type).append("; ")
				.append(CLASS).append("=").append(this.clazz).append("; ")
				.append(R_CODE).append("=").append(this.rcode).append("; ")
				.append(DURATION_USEC).append("=").append(this.dur_tv_sec_usec).append("; ")
				.append(DURATION).append("=").append(this.duration).append("; ")
				.append(CACHED).append("=").append(this.cached).append("; ")
				.append(PKT_LEN).append("=").append(this.pktlen)
				.append(")")
				.toString();
	}
}
