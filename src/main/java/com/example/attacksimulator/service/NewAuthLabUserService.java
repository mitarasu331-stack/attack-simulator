package com.example.attacksimulator.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.example.attacksimulator.repository.NewAuthLabUserRepository;

@Service
public class NewAuthLabUserService {

	private final NewAuthLabUserRepository newAuthLabUserRepository;

	public NewAuthLabUserService(
			NewAuthLabUserRepository newAuthLabUserRepository) {

		this.newAuthLabUserRepository =
				newAuthLabUserRepository;
	}

	/**
	 * newauthlabのusersテーブルから
	 * username一覧を取得する。
	 *
	 * @return username一覧
	 */
	public List<String> getAllUsernames() {

		return newAuthLabUserRepository
				.findAllUsernames();
	}
}