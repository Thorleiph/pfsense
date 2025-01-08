package com.sm0tnt.pfsense.logs.decoders;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class FilterLogHeader extends FilterLog {
	public static final String RULE_NUMBER = "rulenumber";
	public static final String SUB_RULE_NUMBER = "subrulenumber";
	public static final String ANCHOR = "anchor";
	public static final String TRACKER = "tracker";
	public static final String REAL_INTERFACE = "realinterface";
	public static final String REASON = "reason";
	public static final String ACTION = "action";
	public static final String DIRECTION = "direction";
	public static final String IP_VERSION = "ipversion";

	private int ruleNumber;
	private int subRuleNumber;
	private int anchor;
	private int tracker;
	private String realInterface;
	private String reason;
	private String action;
	private String direction;
	private int ipVersion;

	/**
	 * Constructor.
	 * 
	 * @param ruleNumber    The rule number.
	 * @param subRuleNumber The sub-rule number.
	 * @param anchor        The anchor
	 * @param tracker       The tracker.
	 * @param realInterface The real interface.
	 * @param reason        The reason.
	 * @param action        The action.
	 * @param direction     The direction.
	 * @param ipVersion     The IP version.
	 */
	public FilterLogHeader(int ruleNumber, int subRuleNumber, int anchor, int tracker, String realInterface, String reason, String action, String direction, int ipVersion) {
		this.ruleNumber = ruleNumber;
		this.subRuleNumber = subRuleNumber;
		this.anchor = anchor;
		this.tracker = tracker;
		this.realInterface = realInterface;
		this.reason = reason;
		this.action = action;
		this.direction = direction;
		this.ipVersion = ipVersion;
	}

	/**
	 * @return the ruleNumber
	 */
	public int getRuleNumber() {
		return ruleNumber;
	}

	/**
	 * @return the subRuleNumber
	 */
	public int getSubRuleNumber() {
		return subRuleNumber;
	}

	/**
	 * @return the anchor
	 */
	public int getAnchor() {
		return anchor;
	}

	/**
	 * @return the tracker
	 */
	public int getTracker() {
		return tracker;
	}

	/**
	 * @return the realInterface
	 */
	public String getRealInterface() {
		return realInterface;
	}

	/**
	 * @return the reason
	 */
	public String getReason() {
		return reason;
	}

	/**
	 * @return the action
	 */
	public String getAction() {
		return action;
	}

	/**
	 * @return the direction
	 */
	public String getDirection() {
		return direction;
	}

	/**
	 * @return the ipVersion
	 */
	public int getIpVersion() {
		return ipVersion;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ObjectNode toObjectNode(ObjectNode n) {
		if (n == null)
			n = new ObjectMapper().createObjectNode();

		n.put(RULE_NUMBER, this.ruleNumber);

		if (this.subRuleNumber > -1)
			n.put(SUB_RULE_NUMBER, this.subRuleNumber);

		if (this.anchor > -1)
			n.put(ANCHOR, this.anchor);

		n.put(TRACKER, this.tracker);
		n.put(REAL_INTERFACE, this.realInterface);
		n.put(REASON, this.reason);
		n.put(ACTION, this.action);
		n.put(DIRECTION, this.direction);
		n.put(IP_VERSION, this.ipVersion);

		return n;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		StringBuffer result = new StringBuffer();
		result.append(getClass().getSimpleName()).append("(");
		result.append(RULE_NUMBER).append("=").append(this.ruleNumber);
		if (this.subRuleNumber > -1)
			result.append("; ").append(SUB_RULE_NUMBER).append("=").append(this.subRuleNumber);
		if (this.anchor > -1)
			result.append("; ").append(ANCHOR).append("=").append(this.anchor);
		result.append("; ").append(TRACKER).append("=").append(this.tracker);
		result.append("; ").append(REAL_INTERFACE).append("=").append(this.realInterface);
		result.append("; ").append(REASON).append("=").append(this.reason);
		result.append("; ").append(ACTION).append("=").append(this.action);
		result.append("; ").append(DIRECTION).append("=").append(this.direction);
		result.append("; ").append(IP_VERSION).append("=").append(this.ipVersion);
		result.append(")");

		return result.toString();
	}
}
