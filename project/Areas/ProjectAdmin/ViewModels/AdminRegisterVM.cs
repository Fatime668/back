using project.Utilities;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace project.Areas.ProjectAdmin.ViewModels
{
    public class AdminRegisterVM
    {
        [Required, StringLength(maximumLength: 20)]
        public string Firstname { get; set; }
        [Required, StringLength(maximumLength: 20)]

        public string Lastname { get; set; }
        [Required, StringLength(maximumLength: 20)]

        public string Username { get; set; }
        [Required, DataType(DataType.EmailAddress)]

        public string Email { get; set; }
        [Required, DataType(DataType.Password)]

        public string Password { get; set; }
        [Required, DataType(DataType.Password), Compare(nameof(Password))]

        public string ConfirmPassword { get; set; }
        [Required]
        public List<Roles> Roles { get; set; }
        public string TermsConditions { get; set; }
    }
}
