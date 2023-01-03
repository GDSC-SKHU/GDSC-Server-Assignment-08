package com.gdsc.jwtexample.repository;

import com.gdsc.jwtexample.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByMemberId(String username); // 가입되어 있는 memberId가 있는지 확인
}
