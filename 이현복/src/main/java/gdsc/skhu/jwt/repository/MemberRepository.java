package gdsc.skhu.jwt.repository;

import gdsc.skhu.jwt.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    // User이름을 찾을 수 있도록 하는 findByUsername
    Optional<Member> findByMemberId(String username);
}