package vti.dtn.account_service.service.impl;

import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.modelmapper.TypeToken;
import org.springframework.stereotype.Service;
import vti.dtn.account_service.dto.AccountDTO;
import vti.dtn.account_service.repository.AccountRepository;
import vti.dtn.account_service.service.AccountService;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AccountServiceImpl implements AccountService {

    private final ModelMapper modelMapper;
    private final AccountRepository accountRepository;

    @Override
    public List<AccountDTO> getListAccounts() {
        return modelMapper.map(accountRepository.findAll(), new TypeToken<List<AccountDTO>>() {}.getType());
    }
}
