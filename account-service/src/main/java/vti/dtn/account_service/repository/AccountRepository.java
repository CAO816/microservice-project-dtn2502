package vti.dtn.account_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import vti.dtn.account_service.entity.Account;

public interface AccountRepository extends JpaRepository<Account, Integer> {
}
