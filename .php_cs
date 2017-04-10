<?php

use Symfony\CS\Config;
use Symfony\CS\Finder;
use Symfony\CS\FixerInterface;

$fixers = [
    '-psr0',
    'short_array_syntax',
];

return Config::create()
    ->finder(Finder::create()->in(__DIR__))
    ->fixers($fixers)
    ->level(FixerInterface::PSR2_LEVEL)
    ->setUsingCache(true);
