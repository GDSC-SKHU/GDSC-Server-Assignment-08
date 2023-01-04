package com.example.jwt.repository;

import com.example.jwt.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

// username을 통해 member id를 찾는 findByMemberID 메소드
public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByMemberId(String username);
}