<?php

namespace Database\Seeders;

use App\Services\SocAdminAccountServiceR1;
use Illuminate\Database\Seeder;

class SocAdminSeederR1 extends Seeder
{
    public function run(): void
    {
        app(SocAdminAccountServiceR1::class)->ensureAdminAccount();
    }
}
