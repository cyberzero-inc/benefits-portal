package com.acme.benefits.portal.web;

import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.acme.benefits.portal.domain.Member;
import com.acme.benefits.portal.service.EnrollmentService;

/**
 * Self-service enrollment.
 *
 * Created: 18 Jun 2008  D. Farrow
 */
@Controller
@RequestMapping("/enrollment")
public class EnrollmentController {

    private static final Logger log = Logger.getLogger(EnrollmentController.class);

    @Autowired
    private EnrollmentService service;

    @RequestMapping(method = RequestMethod.GET)
    public String show(ModelMap model) {
        List<Map<String, String>> plans = service.availablePlans();
        model.addAttribute("plans", plans);
        return "enrollment";
    }

    @RequestMapping(method = RequestMethod.POST)
    public String submit(@RequestParam("memberId") String memberId,
                         @RequestParam("ssn") String ssn,
                         @RequestParam("planCode") String planCode,
                         ModelMap model) {
        try {
            Member member = new Member(memberId, ssn);
            service.enroll(member, planCode);
            model.addAttribute("memberId", memberId);
            return "enrollment-confirmed";
        } catch (Exception e) {
            log.error("enrollment failed for " + memberId, e);
            return "error";
        }
    }
}
