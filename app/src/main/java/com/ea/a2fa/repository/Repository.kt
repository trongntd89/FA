package com.ea.a2fa.repository

import com.ea.a2fa.Account

interface Repository {
  fun save(data: Account)
  fun getAll(): List<Account>
}
