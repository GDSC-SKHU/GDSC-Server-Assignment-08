package gdsc.skhu.jwtskhu.repository;

import gdsc.skhu.jwtskhu.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;



public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByMemberId(String username);
}
