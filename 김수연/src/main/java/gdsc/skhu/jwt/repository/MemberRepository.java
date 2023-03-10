package gdsc.skhu.jwt.repository;

import gdsc.skhu.jwt.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member,Long>

{
    Optional<Member> findByMemberId(String username);

}
