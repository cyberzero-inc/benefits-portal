package com.acme.benefits.portal.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.acme.benefits.portal.crypto.RecordCipher;
import com.acme.benefits.portal.domain.Member;

/**
 * Enrollment service.
 *
 * Created: 18 Jun 2008  D. Farrow
 *
 * Writes to the same ENROLLMENT table the servlet application uses, so the
 * SSN column carries two encryption formats: 3DES rows from the servlets and
 * AES rows from here. Readers try AES first and fall back.
 */
@Service
public class EnrollmentService {

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private RecordCipher cipher;

    @Transactional
    public void enroll(Member member, String planCode) throws Exception {
        String sealedSsn = cipher.seal(member.getSsn());
        jdbc.update(
            "INSERT INTO ENROLLMENT (MEMBER_ID, SSN_ENC, SSN_FORMAT, PLAN_CODE) VALUES (?, ?, ?, ?)",
            new Object[] { member.getMemberId(), sealedSsn, "AES128", planCode });
    }

    public List<Map<String, String>> availablePlans() {
        List<Map<String, String>> plans = new ArrayList<Map<String, String>>();
        for (Object row : jdbc.queryForList("SELECT PLAN_CODE, PLAN_NAME FROM PLAN WHERE ACTIVE = 'Y'")) {
            Map<String, String> plan = new HashMap<String, String>();
            plan.put("code", String.valueOf(((Map<?, ?>) row).get("PLAN_CODE")));
            plan.put("name", String.valueOf(((Map<?, ?>) row).get("PLAN_NAME")));
            plans.add(plan);
        }
        return plans;
    }
}
