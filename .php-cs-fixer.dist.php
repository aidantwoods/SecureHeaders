<?php

// use PhpCsFixer\Config;
// use PhpCsFixer\Finder;

// $finder = Finder::create()->in(__DIR__);

// $rules = [
//     '@PSR2' => true,
//     'array_syntax' => [
//         'syntax' => 'short',
//     ],
//     'braces' => [
//          'position_after_control_structures'   => 'next',
//          'position_after_return_type_hint'     => 'next',
//          'position_after_anonymous_constructs' => 'next',
//     ],
//     'not_operator_with_space' => true,
//     'return_type_declaration' => [
//         'space_before' => 'one',
//     ],
// ];
// return Config::create()
//     ->setRules($rules)
//     ->setFinder($finder)
//     ->setUsingCache(false);


$finder = (new \PhpCsFixer\Finder())
    ->in(__DIR__.'/src')
;

return (new \PhpCsFixer\Config())
    ->setRules([
        '@PER-CS' => true,
        '@PHP82Migration' => true,
        'array_syntax' => ['syntax' => 'short'],

        'braces_position' => [
            'control_structures_opening_brace' => 'next_line_unless_newline_at_signature_end',
            // 'position_after_control_structures'   => 'next',
            // 'position_after_functions_and_oop_constructs' => 'next',
            // 'position_after_return_type_hint'     => 'next',
            // 'position_after_anonymous_constructs' => 'next',
        ],
        'not_operator_with_space' => true,
        'return_type_declaration' => [
            'space_before' => 'one',
        ],
    ])
    ->setFinder($finder)
;
