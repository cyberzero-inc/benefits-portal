package com.acme.benefits.portal.domain;

/** A benefits member. */
public class Member {

    private final String memberId;
    private final String ssn;

    public Member(String memberId, String ssn) {
        this.memberId = memberId;
        this.ssn = ssn;
    }

    public String getMemberId() {
        return memberId;
    }

    public String getSsn() {
        return ssn;
    }
}
